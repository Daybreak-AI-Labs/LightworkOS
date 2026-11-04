"""Channel-driven server mode.

``maverick serve`` starts a long-running process that:
  - reads enabled channels from config (Telegram, Discord, Slack, Signal,
    WhatsApp, SMS, Email, Matrix, iMessage)
  - listens on each one
  - for each incoming message, creates a goal and dispatches the swarm
  - sends the final result (or a truthful queued acknowledgement) via the same channel

Each user gets their own goal/episode in the world model so context is
preserved across messages. Budget caps still apply per-message.

Safety: input and output are run through Agent Shield if installed.
Tool-call scans happen inside the agent loop (see agent.py). All scans
fail open with a warning if shield isn't available.

Resilience: each channel runs in its own asyncio task. A single channel
crashing logs an error but doesn't take the others down.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from pathlib import Path

from .config import load_config
from .llm import LLM
from .sandbox import build_sandbox
from .world_model import (
    WorldModel,
    close_world_if_owned,
    open_world,
    world_for_tenant,
)

log = logging.getLogger(__name__)


def _channel_conversation_user(msg, principal_id: str, memory_user_id: str) -> str:
    """Keep room/thread history separate without changing the owner's identity."""
    recipient = str(msg.user_id)
    thread = str(getattr(msg, "conversation_ref", None) or "")
    # Slack DMs (and legacy Teams chats) already used the sender-only key.
    # Keep it so an open question survives an upgrade. Room-based Slack
    # messages carry an explicit thread anchor and take the scoped key below.
    if not thread and (recipient == principal_id or msg.channel in {"slack", "teams"}):
        return memory_user_id
    context = json.dumps([recipient, thread], separators=(",", ":"))
    digest = hashlib.sha256(context.encode("utf-8")).hexdigest()
    return f"{memory_user_id}:conversation:{digest}"


def _channel_answer_text(msg) -> str:
    """Email's generated Subject line is routing metadata, not the answer."""
    text = msg.text.strip()
    if msg.channel == "email" and text.startswith("Subject: ") and "\n\n" in text:
        text = text.split("\n\n", 1)[1].strip()
    return text


def _question_id_required(msg) -> bool:
    """A Slack room thread is task-specific; inboxes and topics are long lived."""
    return not (msg.channel == "slack" and getattr(msg, "conversation_ref", None))


def _question_reply(goal_id: int, questions: list, *, require_id: bool = False) -> str:
    lines = [f"Question #{q.id} for task #{q.goal_id}: {q.question}" for q in questions]
    if len(questions) == 1 and not require_id:
        instructions = "Reply here with your answer and I’ll continue this task."
    else:
        instructions = ("Reply with the question number and your answer, for example "
                        f"#{questions[0].id} your answer. Send a new request normally. "
                        "I’ll continue this task when its questions are answered.")
    return "\n".join([*lines, instructions])


def queued_channel_question(watch: dict, msg, account_sha256: str) -> tuple[str | None, bool]:
    """Read a queued goal's question under its original sender and tenant.

    The second return value retires a watch whose goal finished without an
    open question. An unavailable identity or world keeps it for later review.
    """
    from .oidc import oidc_enabled
    from .paths import tenant_by_user_enabled, tenant_scope
    from .personal_identity import CHANNELS, account_identity

    principal = msg.principal_id
    if oidc_enabled():
        if msg.channel not in {"slack", "teams"}:
            return None, False
        from . import channel_oidc_bridge

        principal = channel_oidc_bridge.resolve(
            msg.channel, account_sha256, msg.provider_tenant_id,
            msg.provider_sender_id,
        )
        if not principal:
            return None, False
    expected_tenant = f"{msg.channel}:{principal}" if tenant_by_user_enabled() else None
    if watch.get("tenant") != expected_tenant:
        return None, False
    memory_user_id = (account_identity(principal, account_sha256)
                      if msg.channel in CHANNELS and account_sha256 else principal)
    if _linked_channel_refusal(msg.channel, memory_user_id, account_sha256):
        return None, False
    owner = f"user:{msg.channel}:{memory_user_id}"
    execution_principal = f"user:{msg.channel}:{principal}"
    if (watch.get("owner") != owner
            or watch.get("execution_principal") != execution_principal):
        return None, False

    from .world_model import close_world_if_owned, open_world

    with tenant_scope(tenant=expected_tenant):
        world = open_world()
        try:
            goal_id = watch.get("goal_id")
            goal = world.get_goal(goal_id)
            if goal is None or goal.owner != owner or goal.execution_principal != execution_principal:
                # The sender's identity matched above, so this is about the task
                # itself: erased, or now someone else's. It can never ask this
                # sender anything again; a kept watch would hold its intake
                # record (never compacted) and every recovery pass forever.
                return None, True
            questions = [
                q for q in world.open_channel_questions(
                    watch["conversation_id"], owner, execution_principal,
                ) if q.goal_id == goal_id
            ]
            if questions:
                text = _question_reply(goal_id, questions,
                                       require_id=_question_id_required(msg))
                try:
                    from maverick_shield import Shield
                except ImportError:
                    pass
                else:
                    verdict = Shield.from_config().scan_output(text)
                    if not verdict.allowed:
                        text = (f"Task #{goal_id} needs an answer, but its question "
                                "cannot be shown in this chat. Open Lightwork to review it.")
                return text, False
            return None, goal.status in {"blocked", "done", "failed", "cancelled"}
        finally:
            close_world_if_owned(world)


def _reclaim_tenant_orphans() -> int:
    """Reclaim orphan goals across every per-tenant ``world.db`` on startup.

    The default-world reclaim in :meth:`Server.run` only sweeps
    ``~/.maverick/world.db``. With per-user tenancy on, each tenant has its own
    ``~/.maverick/tenants/<t>/world.db`` whose goals left ``active``/``pending``
    by a crash would otherwise never be reclaimed.

    No-op (returns 0) when ``tenant_by_user_enabled()`` is off -- single-tenant
    behaviour is unchanged. Otherwise enumerate the existing tenant dirs and
    reclaim each tenant's world through a temporary ``WorldModel`` instance,
    summing the counts without populating the live tenant cache.

    Fail-soft: a missing tenants dir or a bad/unreadable tenant entry is
    skipped, never crashing startup.
    """
    from .paths import maverick_home, tenant_by_user_enabled

    if not tenant_by_user_enabled():
        return 0
    tenants_dir = maverick_home() / "tenants"
    try:
        entries = list(tenants_dir.iterdir())
    except OSError:  # missing dir (no tenant has run yet) or unreadable -> nothing to sweep
        return 0
    total = 0
    for entry in entries:
        try:
            if not entry.is_dir():
                continue
            world_db = entry / "world.db"
            if not world_db.is_file():
                continue
            with WorldModel(world_db) as world:
                total += world.reclaim_orphan_goals()
        except Exception:  # one bad tenant dir must not abort the sweep
            log.exception("orphan reclaim failed for tenant dir %s", entry.name)
    return total


def _completed_reply(completed, goal_id: int, channel: str = "") -> str:
    """A finished task's reply: an agent-written answer carries the AI mark;
    a stop or failure message is the product's own words."""
    if completed.status != "done":
        return completed.result
    from .compliance import label_ai_answer
    return label_ai_answer(completed.result, goal_id, channel=channel or "")


class Server:
    def __init__(
        self,
        world: WorldModel,
        llm: LLM,
        sandbox=None,
        max_depth: int = 3,
        *,
        owns_world: bool = False,
        owns_sandbox: bool | None = None,
    ):
        created_sandbox = sandbox is None
        self.world = world
        self._db_path: Path | None = None
        self.llm = llm
        self.sandbox = build_sandbox() if sandbox is None else sandbox
        self.max_depth = max_depth
        # Embedders commonly inject their own world/sandbox and retain their
        # lifecycle.  ``build_from_config`` opts into ownership explicitly so
        # the long-lived ``serve`` process can release a Postgres connection or
        # pool without ever closing a caller-owned dependency.
        self._owns_world = bool(owns_world)
        self._owns_sandbox = (
            created_sandbox if owns_sandbox is None else bool(owns_sandbox)
        )
        self._runtime_receipt = None
        self._runtime_configuration_native = False
        self._resources_closed = False
        self._stopping = False
        self._stopped = False
        self._channels: list = []
        self._tasks: list[asyncio.Task] = []
        self._shield = None
        try:
            from maverick_shield import Shield
            self._shield = Shield.from_config()
            if self._shield.enabled:
                log.info("Agent Shield enabled (profile=%s)", self._shield.profile)
        except ImportError:
            log.warning("maverick-shield not installed; running without safety scans")

    def _message_tenant_world(self, msg, principal_id: str):
        """Resolve one message's tenant and world under the isolation policy."""
        from .paths import tenant_by_user_enabled

        tenant = (
            f"{msg.channel or 'unknown'}:{principal_id}"
            if tenant_by_user_enabled()
            else None
        )
        if tenant is None:
            world = self.world
        else:
            if self._db_path is not None:
                raise RuntimeError("An explicit database cannot be combined with per-user workspace selection.")
            # Postgres is one shared transactional backend whose row-level
            # tenant boundary comes from tenant_scope/current_tenant_strict.
            # Creating a tenant SQLite world here silently splits channel
            # writes from the configured Postgres dashboard and workers.
            from .world_model_backends import PostgresWorldModel

            if isinstance(self.world, PostgresWorldModel):
                world = self.world
            else:
                world = world_for_tenant(tenant)
        return tenant, world

    def _tenant_door_refusal(self, tenant: str | None) -> str | None:
        """Read-only admission check for a per-tenant message at the channel door.

        Returns a user-facing refusal string, or None to admit. Covers the
        roster (suspended), the provisioned daily-spend cap, and plan feature
        gating (the ``channels`` entitlement). Registry/policy errors refuse
        admission rather than silently discarding a suspension or spend cap.

        ``tenant`` is None for legacy serve mode, but ``feature_allowed`` can
        still resolve an active tenant from MAVERICK_TENANT/client binding.
        """
        try:
            from .tenant.registry import (
                TenantSuspended,
                assert_tenant_active,
                tenant_over_quota,
            )
        except Exception:
            log.exception("tenant policy module unavailable; refusing message")
            return "⚠ Workspace policy is unavailable. Try again later."
        if tenant is not None:
            try:
                assert_tenant_active(tenant)
            except TenantSuspended:
                log.warning("message refused: tenant %s suspended", tenant)
                return "⚠ This workspace is suspended. Contact your administrator."
            except Exception:
                log.exception("tenant roster check failed; refusing")
                return "⚠ Workspace policy is unavailable. Try again later."
            try:
                quota_reason = tenant_over_quota(tenant)
            except Exception:
                log.exception("tenant quota check failed; refusing")
                return "⚠ Workspace quota state is unavailable. Try again later."
            if quota_reason:
                log.warning("message refused: %s", quota_reason)
                return f"⚠ {quota_reason}"

        # Plan feature gating: a registered tenant whose plan lacks the
        # "channels" entitlement may not drive the agent over a channel. No-op
        # for unprovisioned per-user tenant ids (feature_allowed admits anything
        # not in the registry), so the default tenant_by_user path is unaffected.
        # When tenant is None, feature_allowed resolves the active deployment
        # tenant (MAVERICK_TENANT/client binding) before deciding.
        from .billing import feature_allowed
        try:
            channels_allowed = feature_allowed("channels", tenant=tenant)
        except Exception:
            log.exception("tenant channel entitlement check failed; refusing")
            return "⚠ Workspace policy is unavailable. Try again later."
        if not channels_allowed:
            log.warning("message refused: tenant %s plan lacks channel access", tenant)
            return ("⚠ This workspace's plan does not include channel access. "
                    "Contact your administrator to upgrade.")
        return None

    async def _handle_message(self, msg) -> str:
        if self._shield is not None:
            verdict = self._shield.scan_input(msg.text)
            if not verdict.allowed:
                return f"⚠ Blocked: {'; '.join(verdict.reasons)}"

        from .oidc import OIDCError, oidc_enabled, verify_oidc_token
        from .paths import tenant_scope

        # The authenticated sender. Room-based adapters keep msg.user_id as the
        # reply target and expose the human via msg.principal_id; the tenant, the
        # conversation key, and the runner's user_id must ALL agree on it -- else a
        # user's world.db lands under a different tenant than their memory/audit.
        # An explicit ID token always has priority: a bad token cannot inherit
        # a previously linked chat account. First-party Slack/Teams delivery
        # can instead use a separately confirmed OIDC bridge, but only with a
        # current durable app receipt and exact provider account/sender tuple.
        if oidc_enabled():
            token = _extract_oidc_token(msg)
            if token or _oidc_token_present(msg):
                try:
                    principal_id = verify_oidc_token(token).principal
                except OIDCError:
                    log.warning("OIDC authentication failed for inbound %s message", msg.channel or "unknown")
                    return "⚠ Authentication failed: OIDC token is missing or invalid."
            elif msg.channel in {"slack", "teams"}:
                from . import channel_oidc_bridge

                account_sha256 = getattr(msg, "_verified_channel_account_sha256", None)
                provider_tenant = getattr(msg, "provider_tenant_id", None)
                sender_id = getattr(msg, "provider_sender_id", None)
                try:
                    proof_reply = channel_oidc_bridge.observe(
                        msg.channel, account_sha256, provider_tenant, sender_id, msg.text,
                    )
                    if proof_reply is not None:
                        return proof_reply
                    principal_id = channel_oidc_bridge.resolve(
                        msg.channel, account_sha256, provider_tenant, sender_id,
                    )
                except Exception:
                    log.exception("Chat identity proof unavailable for %s", msg.channel)
                    principal_id = None
                if not principal_id:
                    return ("⚠ Connect this chat account from My work before asking "
                            "Lightwork to start a task.")
            else:
                return "⚠ Authentication failed: OIDC token is missing or invalid."
        else:
            principal_id = getattr(msg, "principal_id", msg.user_id)

        # Resolve the per-tenant world ONCE. When per-user tenancy is on, this
        # message's goal/conversation/turns land in that user's own world.db
        # (~/.maverick/tenants/<channel>:<principal_id>/world.db) -- the SAME
        # tenant the tenant_scope() below pins for cross-session memory + audit,
        # so all three stores stay co-located. Off (default) -> tenant is None and
        # we reuse the SHARED self.world unchanged (``world is self.world``), so
        # the legacy single-tenant path is byte-for-byte identical and we never
        # open a second connection to ~/.maverick/world.db. self.world also still
        # backs startup orphan-reclaim and the dashboard. If per-user tenant
        # resolution fails, reject the message rather than running attacker input
        # against the shared world and breaking tenant isolation.
        try:
            tenant, world = self._message_tenant_world(msg, principal_id)
        except Exception:
            log.exception("tenant world resolution failed; rejecting message")
            return "⚠ Tenant isolation is unavailable for this message. Try again later."

        # Pin the authenticated tenant across the *entire* lifecycle. Postgres
        # derives INSERT tenant_id values and read predicates from this context,
        # so entering it only around dispatch would leave the conversation and
        # goal rows unscoped. SQLite also benefits: attachment/audit paths and
        # the selected tenant world now share one unambiguous context.
        with tenant_scope(tenant=tenant):
            return await self._handle_message_in_tenant(
                msg, principal_id=principal_id, tenant=tenant, world=world,
            )

    async def _handle_message_in_tenant(
        self, msg, *, principal_id: str, tenant: str | None, world,
    ) -> str:
        """Process an authenticated message inside its already-pinned tenant."""
        # Multi-tenant serve: enforce the tenant roster + plan at the channel
        # door BEFORE any goal is created. No-op until an operator provisions
        # tenants. Read-only refusal reasons (suspended / over daily-spend cap /
        # plan lacks channel access) are returned as a message; None = admit.
        refusal = self._tenant_door_refusal(tenant)
        if refusal:
            return refusal

        # The adapter has authenticated the sender and tenant. A linking
        # command is control-plane proof, never a prompt or remembered turn.
        from .personal_identity import CHANNELS, account_identity, prove_channel_command
        account_sha256 = getattr(msg, "_verified_channel_account_sha256", None)
        memory_user_id = (account_identity(principal_id, account_sha256)
                          if msg.channel in CHANNELS and account_sha256 else principal_id)
        identity_refusal = _linked_channel_refusal(msg.channel, memory_user_id, account_sha256)
        if identity_refusal:
            return identity_refusal
        try:
            proof_reply = prove_channel_command(msg.text, channel=msg.channel or "unknown", user_id=memory_user_id,
                                                sender_id=getattr(msg, "principal_id", None), account_sha256=account_sha256,
                                                private_destination=getattr(msg, "_verified_private_destination", None))
        except Exception:
            log.warning("Personal identity proof unavailable")
            if msg.text.startswith("LIGHTWORK LINK"):
                return "Identity linking could not be confirmed. Check My Data before retrying."
            proof_reply = None
        if proof_reply is not None:
            return proof_reply

        # Per-tenant concurrency ceiling (noisy-neighbor protection). Derived
        # from the tenant's plan entitlement; no-op when tenant is None or the
        # plan is unlimited. Held across the whole goal run and released in the
        # finally below so a crash never leaks a slot.
        from .tenant import concurrency as tenant_concurrency
        try:
            acquired = tenant_concurrency.acquire(tenant)
        except Exception:
            log.exception("tenant concurrency policy failed; refusing")
            return "⚠ Workspace policy is unavailable. Try again later."
        if not acquired:
            log.warning("message refused: tenant %s at concurrency ceiling", tenant)
            return ("⚠ This workspace is at its concurrent-task limit. "
                    "Try again once a running task finishes.")

        try:
            # Multi-turn: a single (channel, user_id) gets one conversation
            # row. Every inbound message becomes a 'user' turn; the
            # orchestrator's final answer is appended as an 'assistant' turn
            # inside the dispatched run so future messages have history.

            # EU AI Act Article 50: disclose AI to new channel users on
            # first turn. `first_turn_disclosure` checks the conversation
            # row (creates if needed) and returns None on follow-up turns.
            from .compliance import first_turn_disclosure
            disclosure = first_turn_disclosure(
                world,
                channel=msg.channel or "unknown",
                user_id=_channel_conversation_user(msg, principal_id, memory_user_id),
            )

            conversation = world.get_or_create_conversation(
                channel=msg.channel or "unknown",
                user_id=_channel_conversation_user(msg, principal_id, memory_user_id),
            )

            from .deployment import require_enterprise_or_die
            require_enterprise_or_die()

            # Persist the exact principal the runner will execute under.  The
            # identity is opaque and stays in the database; tenant path code
            # independently percent-encodes it before any filesystem use.
            execution_user_id = f"{msg.channel or 'unknown'}:{principal_id}"
            owner = f"user:{msg.channel or 'unknown'}:{memory_user_id}"
            execution_principal = f"user:{execution_user_id}"
            answer = self._channel_answer(
                world, msg, conversation.id, owner, execution_principal,
            )
            if answer is not None:
                goal_id, answered_question, early_reply = answer
                if early_reply is not None:
                    return self._channel_output(early_reply, disclosure)
            else:
                answered_question = None
                goal_id = self._new_channel_goal(
                    world, msg, conversation.id, owner, execution_principal,
                )

            # Inbound channel attachments (Slack files, email/Telegram
            # attachments) become goal attachments, exactly like a dashboard
            # upload: store() enforces the size/mime/magic-byte rules, then
            # text companions (transcripts, extracted doc text) generate so
            # the agent's first message can carry them. Best-effort — a
            # rejected or broken file never blocks the message.
            if getattr(msg, "attachments", None):
                stored_any = self._store_inbound_attachments(
                    world, goal_id, msg.attachments)
                if stored_any:
                    import asyncio as _asyncio

                    from .attachments import generate_companions
                    try:
                        await _asyncio.to_thread(
                            generate_companions, world, goal_id)
                    except Exception:  # pragma: no cover -- never blocks
                        log.warning("companion generation failed",
                                    exc_info=True)

            try:
                # The caller's tenant scope covers queue-envelope creation and
                # local execution. asyncio.to_thread preserves this context for
                # the synchronous dispatcher without blocking a channel event
                # loop on broker or gRPC I/O.
                from .runner import run_goal_in_background_async
                dispatch_status = await run_goal_in_background_async(
                    goal_id, max_depth=self.max_depth,
                    channel=msg.channel or "unknown",
                    user_id=execution_user_id,
                    conversation_id=conversation.id,
                    **({"db_path": self._db_path} if self._db_path is not None else {}),
                )
            except Exception:
                log.exception("goal #%s dispatch failed", goal_id)
                # A transport failure may follow remote acceptance. Do not
                # repaint a pending goal or suggest blind replay.
                return (f"⚠ Task #{goal_id} may still be running. Check its status "
                        "before trying again.")

            if dispatch_status == "queued":
                # The worker may ask later. The durable channel receipt keeps
                # this binding so the adapter can deliver that question after
                # the initial queued acknowledgement has been sent.
                msg._channel_question_watch = {
                    "goal_id": goal_id, "conversation_id": conversation.id,
                    "tenant": tenant, "owner": owner,
                    "execution_principal": execution_principal,
                }
                # QueueDispatcher returns after authenticated enqueue. It cannot
                # supply a final channel reply yet, so be explicit rather than
                # pretending the goal completed (or holding this event loop open
                # while a worker may run for many minutes).
                result = (
                    f"Goal #{goal_id} was queued for background processing. "
                    "Check its status in Lightwork."
                )
            elif dispatch_status in {None, "error"}:
                # The dispatcher could not establish whether a remote owner
                # accepted the task. Never advise an automatic replay.
                return (f"Task #{goal_id} may still be running. Check its status "
                        "before trying again.")
            else:
                # LocalThreadDispatcher and gRPC wait for a terminal status. Read
                # the result from the authoritative world rather than treating the
                # status string itself as an answer. A remote worker must share the
                # same world backend for this to succeed.
                completed = world.get_goal(goal_id)
                questions = (world.open_questions(goal_id)
                             if completed is not None and completed.status == "blocked" else [])
                if questions:
                    result = _question_reply(goal_id, questions,
                                             require_id=_question_id_required(msg))
                elif completed is not None and completed.result is not None:
                    result = _completed_reply(completed, goal_id, getattr(msg, "channel", ""))
                else:
                    known_status = (
                        dispatch_status
                        if dispatch_status in {"done", "blocked", "failed", "cancelled"}
                        else "unknown"
                    )
                    result = (
                        f"Goal #{goal_id} finished with status {known_status}, "
                        "but its result is not available in this process."
                    )

            if answered_question is not None:
                result = (f"I saved your answer to Question #{answered_question.id} "
                          f"and continued task #{goal_id}.\n\n{result}")

            return self._saved_channel_output(world, msg, goal_id, result, disclosure,
                owner=owner, execution_principal=execution_principal, principal=principal_id)
        finally:
            # Always free the tenant's concurrency slot, on every exit path.
            tenant_concurrency.release(tenant)

    @staticmethod
    def _new_channel_goal(world, msg, conversation_id, owner, execution_principal):
        from .channel_autorouting import specialist_for

        specialist = specialist_for(msg)
        goal_id = world.create_goal(
            msg.text[:80], msg.text, owner=owner,
            execution_principal=execution_principal,
            **({"domain": specialist} if specialist else {}),
        )
        world.append_turn(conversation_id, "user", msg.text, goal_id=goal_id)
        if specialist:
            log.info("goal #%s routed to specialist %s", goal_id, specialist)
        return goal_id

    @staticmethod
    def _channel_answer(world, msg, conversation_id, owner, execution_principal):
        """Bind a channel reply to one still-open question, or return None."""
        pending = world.open_channel_questions(conversation_id, owner, execution_principal)
        if not pending:
            return (None, None, "") if getattr(msg, "question_reply_only", False) else None
        answer_text = _channel_answer_text(msg)
        selected = re.match(r"^#(\d+)\s*[:.-]?\s+(.+)$", answer_text, re.DOTALL)
        if selected:
            question_id = int(selected.group(1))
            answer_text = selected.group(2).strip()
            question = next((q for q in pending if q.id == question_id), None)
            if question is None:
                message = (f"Question #{question_id} is not open in this conversation.\n"
                           + _question_reply(pending[0].goal_id, pending,
                                             require_id=_question_id_required(msg)))
                return None, None, message
        elif len(pending) == 1 and not _question_id_required(msg):
            question = pending[0]
        elif _question_id_required(msg) and not getattr(msg, "question_reply_only", False):
            # A long-lived inbox can have a blocked task and a fresh request.
            # Only an explicit question id is an answer in that context.
            return None
        else:
            return None, None, _question_reply(pending[0].goal_id, pending,
                                               require_id=_question_id_required(msg))
        if not answer_text:
            return None, None, _question_reply(question.goal_id, [question],
                                               require_id=_question_id_required(msg))
        if not world.answer_open_channel_question(
            question.id, question.goal_id, answer_text,
            conversation_id=conversation_id, owner=owner,
            execution_principal=execution_principal,
        ):
            return None, None, "That question changed while you replied. Check the latest task message."
        world.append_turn(conversation_id, "user", msg.text, goal_id=question.goal_id)
        remaining = world.open_questions(question.goal_id)
        if remaining:
            message = (f"Answer to Question #{question.id} saved for task #{question.goal_id}.\n"
                       + _question_reply(question.goal_id, remaining,
                                         require_id=_question_id_required(msg)))
            return question.goal_id, question, message
        return question.goal_id, question, None

    def _channel_output(self, result: str, disclosure: str | None) -> str:
        if not result:
            return ""
        if self._shield is not None:
            verdict = self._shield.scan_output(result)
            if not verdict.allowed:
                return f"⚠ Output blocked: {'; '.join(verdict.reasons)}"
        return f"{disclosure}\n\n{result}" if disclosure is not None else result

    def _saved_channel_output(self, world, msg, goal_id, result, disclosure, **identity):
        from .channel_reply_results import prepare_reply

        text = self._channel_output(result, disclosure)
        if not text or text.startswith("⚠ Output blocked:"):
            return text
        try:
            if msg.channel == "voice":
                from maverick_channels.voice import require_saved_source

                from .paths import current_tenant_id_strict

                goal = world.get_goal(goal_id)
                if goal is not None and goal.status == "done":
                    source = {"goal_id": goal.id, **identity, "tenant": current_tenant_id_strict(),
                              "channel": msg.channel,
                              "account_sha256": getattr(msg, "_verified_channel_account_sha256", None),
                              "provider_tenant_id": msg.provider_tenant_id,
                              "provider_sender_id": msg.provider_sender_id,
                              "voice_result_sha256": hashlib.sha256((goal.result or "").encode()).hexdigest()}
                    require_saved_source(source)
                    # Voice returns text to the provider, never artifact files.
                    # Bind that answer even when no downloadable artifact exists.
                    msg._channel_reply_material = {"source": source, "files": []}
                    return text
            return prepare_reply(world, msg, goal_id, text, **identity)
        except PermissionError:
            return "This task's saved output is no longer available to this chat account. Open Lightwork to review current access."
        except (ValueError, OSError):
            log.warning("Saved channel output files could not be prepared", exc_info=True)
            return text + "\n\nSaved files could not be prepared for this chat. Open the task in Lightwork to review its output."

    @staticmethod
    def _store_inbound_attachments(world, goal_id: int, items) -> int:
        """Persist channel-delivered files as goal attachments.

        ``items`` is ``IncomingMessage.attachments``: dicts with ``filename``,
        ``mime``, and ``data`` (bytes) — the shape every adapter that
        downloads inbound files produces. Entries without bytes (metadata-only
        adapters) are skipped. Each file passes the same ``attachments.store``
        validation as a dashboard upload; rejects are logged, never raised —
        an attachment must not kill the message. Bounded to the first 10
        items so a hostile sender can't fan out storage work. Returns how
        many were stored.
        """
        from . import attachments as _att
        stored = 0
        total = sum(a.size_bytes for a in world.list_attachments(goal_id))
        for item in list(items)[:10]:
            if not isinstance(item, dict):
                continue
            data = item.get("data")
            filename = str(item.get("filename") or "").strip()
            if not isinstance(data, (bytes, bytearray)) or not data or not filename:
                continue
            mime = str(item.get("mime") or "application/octet-stream")
            try:
                rec = _att.store(goal_id, filename, mime, bytes(data),
                                 existing_total=total)
                world.add_attachment(goal_id, rec.filename, rec.mime,
                                     rec.size_bytes, rec.sha256, str(rec.path))
            except _att.AttachmentRejected as exc:
                log.info("inbound attachment %r rejected: %s", filename, exc)
                continue
            except Exception:  # noqa: BLE001 -- never kill the message
                log.warning("inbound attachment %r not stored", filename,
                            exc_info=True)
                continue
            total += rec.size_bytes
            stored += 1
        return stored

    def add_channel(self, channel) -> None:
        # The durable native handler prepares rich/file replies before custody;
        # decorating send() cannot intercept an adapter's saved-reply transport.
        self._channels.append(channel)

    async def run(self) -> None:
        """Run all channels concurrently. One channel crashing logs but doesn't kill others."""
        if not self._channels:
            raise ValueError("no channels registered")
        # Reclaim any goals stuck in 'active'/'pending' from a prior
        # crash. Without this, SIGKILL/OOM mid-run leaves ghosts that
        # show in /goals forever. Sweeps the default world; with per-user
        # tenancy on, _reclaim_tenant_orphans() also sweeps every tenant's
        # own world.db (a crash strands goals there too).
        try:
            reclaimed = self.world.reclaim_orphan_goals()
            reclaimed += _reclaim_tenant_orphans()
            if reclaimed:
                log.warning("reclaimed %d orphan goal(s) from prior crash", reclaimed)
        except Exception:  # pragma: no cover
            log.exception("orphan goal reclaim failed on serve startup")
        log.info(
            "starting %d channel(s): %s",
            len(self._channels),
            ", ".join(c.name for c in self._channels),
        )
        try:
            # Append incrementally so a later adapter returning an invalid
            # awaitable cannot orphan tasks already started earlier in the
            # channel list.
            self._tasks = []
            for channel in self._channels:
                self._tasks.append(
                    asyncio.create_task(
                        channel.start(), name=f"channel-{channel.name}",
                    )
                )
            from .runtime_configuration import start as start_runtime_receipt
            self._runtime_receipt = start_runtime_receipt("channels") if self._runtime_configuration_native else None
            results = await asyncio.gather(*self._tasks, return_exceptions=True)
            for c, result in zip(self._channels, results, strict=False):
                if isinstance(result, Exception):
                    log.error("channel %s crashed: %s", c.name, result)
        finally:
            # ``asyncio.run`` cancels this coroutine on Ctrl-C.  Perform the
            # channel teardown before releasing the server-owned world so no
            # adapter can race a final callback against a closed Postgres pool.
            await self.stop()

    async def stop(self) -> None:
        if self._stopped or self._stopping:
            return
        self._stopping = True
        try:
            for t in self._tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            await asyncio.gather(
                *(c.stop() for c in self._channels), return_exceptions=True,
            )
        finally:
            self.close()
            self._stopped = True
            self._stopping = False

    def close(self) -> None:
        """Release dependencies owned by this server, once.

        This is synchronous so partial construction failures can clean up
        before an event loop exists.  Cached tenant SQLite worlds remain open
        by design; :func:`close_world_if_owned` closes only caller-owned SQLite
        handles and each independently-created Postgres connection/pool.
        """
        if self._resources_closed:
            return
        self._resources_closed = True
        if self._runtime_receipt is not None:
            self._runtime_receipt.close()
        if self._owns_sandbox:
            close = getattr(self.sandbox, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # pragma: no cover -- teardown is best-effort
                    log.debug("server sandbox close failed", exc_info=True)
        if self._owns_world:
            try:
                close_world_if_owned(self.world)
            except Exception:  # pragma: no cover -- teardown is best-effort
                log.debug("server world close failed", exc_info=True)


def _wire_telegram(server, cfg):
    from maverick_channels.telegram import TelegramChannel
    token = cfg.get("bot_token") or os.environ.get("TELEGRAM_BOT_TOKEN")
    allowed_user_ids = cfg.get("allowed_user_ids")
    allowed_chat_ids = cfg.get("allowed_chat_ids")
    server.add_channel(TelegramChannel(
        handler=server._handle_message,
        token=token,
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
        allowed_chat_ids={str(v) for v in allowed_chat_ids} if allowed_chat_ids is not None else None,
    ))


def _wire_discord(server, cfg):
    from maverick_channels.discord import DiscordChannel
    token = cfg.get("bot_token") or os.environ.get("DISCORD_BOT_TOKEN")
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(DiscordChannel(
        handler=server._handle_message,
        token=token,
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
    ))


def _wire_slack(server, cfg):
    from maverick_channels.slack import SlackChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(SlackChannel(
        handler=server._handle_message,
        app_token=cfg.get("app_token") or os.environ.get("SLACK_APP_TOKEN"),
        bot_token=cfg.get("bot_token") or os.environ.get("SLACK_BOT_TOKEN"),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
        # [channels.slack] thread_replies: answers post under the asking
        # message's thread instead of interleaving into the channel.
        thread_replies=cfg.get("thread_replies"),
        # Approval buttons and slash commands decide against the server's world;
        # [channels.slack] approvals_channel is where new cards are posted.
        world=server.world,
        approvals_channel=cfg.get("approvals_channel"),
    ))


def _wire_signal(server, cfg):
    from maverick_channels.signal import SignalChannel
    phone = cfg.get("phone_number")
    if not phone:
        raise RuntimeError("signal channel requires phone_number in config")
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(SignalChannel(
        handler=server._handle_message,
        phone_number=phone,
        signal_cli_path=cfg.get("signal_cli_path"),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
    ))


def _wire_email(server, cfg):
    from maverick_channels.email import EmailChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(EmailChannel(
        handler=server._handle_message,
        imap_host=cfg["imap_host"],
        imap_user=cfg["imap_user"],
        imap_password=cfg.get("imap_password") or "",
        smtp_host=cfg["smtp_host"],
        smtp_user=cfg["smtp_user"],
        smtp_password=cfg.get("smtp_password") or "",
        smtp_port=cfg.get("smtp_port", 465),
        poll_interval=cfg.get("poll_interval", 30),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
        trusted_authserv_id=cfg.get("trusted_authserv_id") or "",
        oauth_config={key: cfg.get(key) for key in
                      ("email_auth", "oauth_account", "oauth_tenant", "oauth_principal")},
    ))


def _wire_matrix(server, cfg):
    from maverick_channels.matrix import MatrixChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(MatrixChannel(
        handler=server._handle_message,
        homeserver=cfg["homeserver"],
        user_id=cfg["user_id"],
        access_token=cfg.get("access_token") or os.environ.get("MATRIX_ACCESS_TOKEN"),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
    ))




def _wire_bluesky(server, cfg):
    from maverick_channels.bluesky import BlueskyChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(BlueskyChannel(
        handler=server._handle_message,
        handle=cfg.get("handle") or os.environ.get("BLUESKY_HANDLE"),
        password=cfg.get("password") or os.environ.get("BLUESKY_PASSWORD"),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
        poll_interval=cfg.get("poll_interval", 30),
    ))


def _wire_mastodon(server, cfg):
    from maverick_channels.mastodon import MastodonChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(MastodonChannel(
        handler=server._handle_message,
        instance=cfg.get("instance") or os.environ.get("MASTODON_INSTANCE"),
        access_token=cfg.get("access_token") or os.environ.get("MASTODON_ACCESS_TOKEN"),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
        poll_interval=cfg.get("poll_interval", 30),
    ))

def _wire_whatsapp(server, cfg):
    from maverick_channels.whatsapp import WhatsAppChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(WhatsAppChannel(
        handler=server._handle_message,
        account_sid=cfg.get("account_sid") or os.environ.get("TWILIO_ACCOUNT_SID"),
        auth_token=cfg.get("auth_token") or os.environ.get("TWILIO_AUTH_TOKEN"),
        from_number=cfg.get("from_number"),
        port=cfg.get("port", 8765),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
    ))


def _wire_whatsapp_cloud(server, cfg):
    from maverick_channels.whatsapp_cloud import WhatsAppCloudChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(WhatsAppCloudChannel(
        handler=server._handle_message,
        access_token=cfg.get("access_token") or os.environ.get("WHATSAPP_CLOUD_ACCESS_TOKEN"),
        phone_number_id=cfg.get("phone_number_id")
        or os.environ.get("WHATSAPP_CLOUD_PHONE_NUMBER_ID"),
        verify_token=cfg.get("verify_token") or os.environ.get("WHATSAPP_CLOUD_VERIFY_TOKEN"),
        app_secret=cfg.get("app_secret") or os.environ.get("WHATSAPP_CLOUD_APP_SECRET"),
        port=cfg.get("port", 8767),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
    ))


def _wire_threads(server, cfg):
    from maverick_channels.threads import ThreadsChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(ThreadsChannel(
        handler=server._handle_message,
        access_token=cfg.get("access_token") or os.environ.get("THREADS_ACCESS_TOKEN"),
        user_id=cfg.get("user_id") or os.environ.get("THREADS_USER_ID"),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
        poll_seconds=cfg.get("poll_seconds", 30),
    ))


def _wire_rcs(server, cfg):
    from maverick_channels.rcs import RcsChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(RcsChannel(
        handler=server._handle_message,
        agent_id=cfg.get("agent_id") or os.environ.get("RCS_AGENT_ID"),
        service_account_json=cfg.get("service_account_json")
        or os.environ.get("RCS_SERVICE_ACCOUNT_JSON"),
        webhook_token=cfg.get("webhook_token") or os.environ.get("RCS_WEBHOOK_TOKEN"),
        port=cfg.get("port", 8768),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
    ))


def _wire_sms(server, cfg):
    from maverick_channels.sms import SMSChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(SMSChannel(
        handler=server._handle_message,
        account_sid=cfg.get("account_sid") or os.environ.get("TWILIO_ACCOUNT_SID"),
        auth_token=cfg.get("auth_token") or os.environ.get("TWILIO_AUTH_TOKEN"),
        from_number=cfg.get("from_number"),
        port=cfg.get("port", 8766),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
    ))


def _wire_imessage(server, cfg):
    from maverick_channels.imessage import iMessageChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(iMessageChannel(
        handler=server._handle_message,
        poll_interval=cfg.get("poll_interval", 5),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
    ))


def _wire_irc(server, cfg):
    from maverick_channels.irc import IRCChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(IRCChannel(
        server._handle_message,
        cfg.get("server") or os.environ.get("IRC_SERVER"),
        nick=cfg.get("nick", "maverick"),
        port=cfg.get("port", 6697),
        tls=cfg.get("tls", True),
        channels=cfg.get("channels"),
        password=cfg.get("password") or os.environ.get("IRC_PASSWORD"),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
    ))


def _wire_voice(server, cfg):
    from maverick_channels.voice import VoiceChannel, configuration_identity

    from .paths import (
        TenantPolicyError,
        current_tenant_id_strict,
        reset_tenant,
        set_tenant,
        tenant_by_user_enabled,
    )

    expected = configuration_identity(cfg)
    installation_tenant, expected_by_user = current_tenant_id_strict(), tenant_by_user_enabled()
    def current_authority():
        from .config import config_source_errors, load_global_config

        token = set_tenant(installation_tenant)
        try:
            current = load_global_config().get("channels", {}).get("voice", {})
            return (not config_source_errors(include_tenant=False) and current.get("enabled") is True
                    and tenant_by_user_enabled() == expected_by_user and configuration_identity(current) == expected)
        except (TenantPolicyError, ValueError, TypeError, AttributeError):
            return False
        finally:
            reset_tenant(token)

    async def handle(message):
        # Server owns the identity/tenant decision. Caller-scoped receipt
        # custody must not supply a different initial configuration context.
        token = set_tenant(installation_tenant)
        try:
            return await server._handle_message(message)
        finally:
            reset_tenant(token)

    server.add_channel(VoiceChannel(
        handler=handle,
        # Let VoiceChannel resolve the key from the provider-specific env
        # var (VAPI/RETELL/BLAND) when config doesn't pin one explicitly.
        api_key=cfg.get("api_key"),
        phone_number=cfg.get("phone_number"),
        port=cfg.get("port", 8770),
        assistant_id=cfg.get("assistant_id"),
        provider=cfg.get("provider", "vapi"),
        webhook_token=cfg.get("webhook_token") or os.environ.get("VAPI_WEBHOOK_TOKEN"),
        allowed_callers=cfg.get("allowed_callers"),
        current_authority=current_authority,
    ))


def _wire_mattermost(server, cfg):
    from maverick_channels.mattermost import MattermostChannel
    allowed_user_ids = cfg.get("allowed_user_ids")
    server.add_channel(MattermostChannel(
        handler=server._handle_message,
        url=cfg.get("url") or "",
        # The environment wins over the token saved on the Channels page.
        bot_token=os.environ.get("MATTERMOST_BOT_TOKEN") or cfg.get("bot_token"),
        allowed_user_ids={str(v) for v in allowed_user_ids} if allowed_user_ids is not None else None,
        poll_interval=cfg.get("poll_interval", 10),
    ))


def _wire_teams(server, cfg):
    from maverick_channels.teams import TeamsChannel, channel_config
    settings = channel_config(cfg)
    server.add_channel(TeamsChannel(
        handler=server._handle_message,
        app_id=settings["app_id"],
        app_password=settings["app_password"],
        tenant_id=settings["tenant_id"] or None,
        allowed_tenants=settings["allowed_tenants"] or None,
        allowed_user_ids=settings["allowed_users"],
        # [channels.teams] approvals_enabled: approval cards in Teams, decided
        # through the dashboard's own decision path.
        approvals_enabled=settings["approvals_enabled"],
        port=settings["port"],
        bot_name=settings["bot_name"],
        service_url=settings["service_url"],
    ))


_WIRES = {
    "telegram": _wire_telegram,
    "discord":  _wire_discord,
    "slack":    _wire_slack,
    "signal":   _wire_signal,
    "email":    _wire_email,
    "matrix":   _wire_matrix,
    "bluesky":  _wire_bluesky,
    "mastodon": _wire_mastodon,
    "whatsapp": _wire_whatsapp,
    "whatsapp_cloud": _wire_whatsapp_cloud,
    "threads": _wire_threads,
    "rcs": _wire_rcs,
    "sms":      _wire_sms,
    "imessage": _wire_imessage,
    "voice":    _wire_voice,
    "irc":      _wire_irc,
    "mattermost": _wire_mattermost,
    "teams": _wire_teams,
}

# Tables under [channels] that configure every channel rather than naming one.
_SHARED_CHANNEL_TABLES = frozenset({"routing"})


def _build_plugin_channel(cls, name: str, handler, options: dict):
    """Instantiate one plugin channel class for ``[channels.<name>]``.

    A plugin may provide ``from_config(handler, options)``; otherwise it is
    constructed with the handler alone and receives its table as ``config``.
    """
    factory = getattr(cls, "from_config", None)
    if callable(factory):
        channel = factory(handler, dict(options))
    else:
        channel = cls(handler)
        channel.config = dict(options)
    for method in ("start", "send", "stop"):
        if not callable(getattr(channel, method, None)):
            raise TypeError(f"plugin channel has no {method}()")
    if not getattr(channel, "name", None):
        channel.name = name
    return channel


def _wire_plugin_channels(server, channels_cfg: dict) -> None:
    """Start enabled ``[channels.<name>]`` tables that name an installed
    channel plugin (``maverick.channels`` entry point), exactly like the
    built-in channels: same handler (Shield, workspace policy, disclosure,
    intake), same start/stop lifecycle. A plugin that cannot be found or
    fails to load is skipped with a warning; the other channels still run."""
    wanted = {name: table for name, table in channels_cfg.items()
              if isinstance(table, dict) and table.get("enabled") is True
              and name not in _WIRES and name not in _SHARED_CHANNEL_TABLES}
    if not wanted:
        return
    try:
        from .plugins import discover_channels
        found = dict(discover_channels())
    except Exception as e:
        log.warning("channel plugins could not be discovered (%s); not starting %s",
                    e, ", ".join(sorted(wanted)))
        return
    for name, table in sorted(wanted.items()):
        cls = found.get(name)
        if cls is None:
            log.warning("channel %s is turned on but no installed channel plugin provides it", name)
            continue
        options = {k: v for k, v in table.items() if k != "enabled"}
        try:
            server.add_channel(_build_plugin_channel(cls, name, server._handle_message, options))
            log.info("enabled plugin channel %s", name)
        except Exception as e:
            log.warning("plugin channel %s failed to load; continuing without it: %s", name, e)


def _advise_channel_tenancy(server) -> None:
    """Warn when a multi-tenant deployment shares one global channel identity.

    Channels are global listeners built once from ``[channels.*]``: a single
    Slack/Telegram/email bot identity per process. Inbound replies still route
    back to the originating channel (no cross-tenant reply leak), but every
    tenant shares that one bot identity and its allow-lists. When distinct
    per-tenant bot identities are required, run one Lightwork instance per tenant
    (the Helm chart + per-tenant ``tenants/<id>/config.toml`` overlay make this
    cheap) rather than many tenants behind one process. Advisory only; never
    blocks boot.
    """
    try:
        from .paths import tenant_by_user_enabled
        from .tenant.registry import list_tenants
        multi = tenant_by_user_enabled() or len(list_tenants()) > 1
        if multi and server._channels:
            log.warning(
                "multi-tenant deployment detected with %d global channel(s) (%s): "
                "all tenants share one bot identity per channel. For distinct "
                "per-tenant bot identities, run one instance per tenant "
                "(see deploy/helm + per-tenant config). See docs/multi-tenancy.md.",
                len(server._channels),
                ", ".join(c.name for c in server._channels),
            )
    except Exception:  # pragma: no cover -- advisory must never block boot
        pass


def build_from_config(db: Path | None = None) -> Server:
    cfg = load_config()
    if db is not None:
        from .grpc_dispatcher import configured_target
        from .paths import tenant_by_user_enabled
        from .world_model_backends import is_postgres_configured

        queue = cfg.get("queue") or {}
        if (not isinstance(queue, dict) or queue.get("backend")
                or configured_target() or tenant_by_user_enabled()
                or is_postgres_configured()):
            raise RuntimeError(
                "--db selects one local database and cannot be combined with "
                "a network worker, Postgres, or per-user workspaces. Use local "
                "execution for that database, or omit --db to use the configured shared workspace."
            )
        db = Path(db).expanduser().resolve()
    # Validate the routes this server can actually instantiate. A credential
    # for an unrelated provider must not unblock startup, while valid keyless
    # localhost and Codex CLI routes must not be rejected.
    from .operator_preflight import (
        _format_route_missing,
        _routed_configuration_missing,
    )

    missing_routes = {
        provider: fields
        for provider, fields in _routed_configuration_missing(cfg).items()
        if fields
    }
    if missing_routes:
        detail = _format_route_missing(missing_routes)
        raise RuntimeError(
            "No LLM provider route is complete "
            f"({detail}). Add the missing key in Lightwork > Settings (or run "
            "'maverick init' on a computer with no Lightwork setup yet), then "
            "run 'maverick preflight'."
        )

    world = open_world(db) if db is not None else open_world()
    sandbox = None
    server = None
    try:
        from .llm import model_for_role

        llm = LLM(model=model_for_role("orchestrator"))
        sandbox_cfg = cfg.get("sandbox", {})
        backend = sandbox_cfg.get("backend")
        # Default workdir mirrors config.get_sandbox()'s documented
        # ~/maverick-workspace default rather than Path.cwd(), so `serve` and
        # the rest of the kernel agree.
        from .config import get_sandbox
        workdir = Path(
            sandbox_cfg.get("workdir", get_sandbox()["workdir"])
        ).expanduser()
        sandbox = build_sandbox(workdir=workdir, backend=backend)
        server = Server(
            world=world,
            llm=llm,
            sandbox=sandbox,
            owns_world=True,
            owns_sandbox=True,
        )
        server._runtime_configuration_native = True
        server._db_path = db

        channels_cfg = cfg.get("channels", {})
        for name, wire in _WIRES.items():
            ch_cfg = channels_cfg.get(name, {})
            if not isinstance(ch_cfg, dict) or not ch_cfg.get("enabled"):
                continue
            try:
                wire(server, ch_cfg)
                log.info("enabled %s channel", name)
            except ImportError as e:
                log.error("channel %s enabled but optional deps missing: %s", name, e)
            except Exception as e:
                log.error("channel %s failed to initialize: %s", name, e)
        _wire_plugin_channels(server, channels_cfg if isinstance(channels_cfg, dict) else {})

        if not server._channels:
            raise RuntimeError(
                "No channels enabled (or all failed to initialize). Edit "
                "~/.maverick/config.toml and set [channels.<name>] enabled = true."
            )

        _advise_channel_tenancy(server)

        _install_goal_dispatcher()

        return server
    except BaseException:
        # A bad provider/sandbox/channel configuration can fail after Postgres
        # has already opened a connection pool.  Construction failures have no
        # event loop or Server.stop() caller, so release owned resources here.
        if server is not None:
            server.close()
        else:
            close = getattr(sandbox, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # pragma: no cover -- preserve root error
                    log.debug("startup sandbox close failed", exc_info=True)
            try:
                close_world_if_owned(world)
            except Exception:  # pragma: no cover -- preserve root error
                log.debug("startup world close failed", exc_info=True)
        raise


def _install_goal_dispatcher() -> None:
    """Install the selected remote dispatcher without weakening on failure."""
    # If [queue] backend selects a task queue, run goals out-of-process on a
    # worker pool instead of in this channel-server process. No-op by default.
    try:
        from .queue_dispatcher import install_from_config
        queue_installed = install_from_config()
    except Exception:  # pragma: no cover -- optional integration failure
        # A selected-but-invalid queue installer pins a rejecting dispatcher.
        # Do not let gRPC or the local default overwrite that security boundary.
        log.exception("queue dispatcher install failed; dispatch remains fail-closed")
        return
    # [grpc_dispatch] target: execute goals on a remote gRPC worker. The
    # queue backend wins when both are configured (it already owns dispatch).
    if not queue_installed:
        try:
            from .grpc_dispatcher import install_from_config as install_grpc
            install_grpc()
        except Exception:  # pragma: no cover -- never block server boot
            log.exception("gRPC dispatcher install failed (running in-process)")


def _extract_oidc_token(msg) -> str:
    """Best-effort extraction of an OIDC ID token from a channel message.

    Channel adapters can pass the token explicitly as ``id_token``/``oidc_token``
    or as a bearer token in ``authorization``. Webhook-style adapters may keep
    the original request/dict on ``raw``; support those header shapes too.
    """
    for attr in ("id_token", "oidc_token"):
        value = getattr(msg, attr, None)
        if isinstance(value, str) and value.strip():
            return value.strip()

    authorization = getattr(msg, "authorization", None)
    if not authorization:
        raw = getattr(msg, "raw", None)
        headers = getattr(raw, "headers", None)
        if headers is None and isinstance(raw, dict):
            headers = raw.get("headers")
        if headers is not None:
            try:
                authorization = (
                    headers.get("authorization") or headers.get("Authorization")
                )
            except AttributeError:
                authorization = None
        if not authorization and isinstance(raw, dict):
            value = raw.get("id_token") or raw.get("oidc_token")
            if isinstance(value, str) and value.strip():
                return value.strip()

    if isinstance(authorization, str):
        prefix = "Bearer "
        if authorization.startswith(prefix):
            return authorization[len(prefix):].strip()
        return authorization.strip()
    return ""


def _oidc_token_present(msg) -> bool:
    """An explicitly supplied, even empty, credential must be verified."""
    for attr in ("id_token", "oidc_token", "authorization"):
        if getattr(msg, attr, None) is not None:
            return True
    raw = getattr(msg, "raw", None)
    if isinstance(raw, dict):
        if any(key in raw for key in ("id_token", "oidc_token")):
            return True
        headers = raw.get("headers")
    else:
        headers = getattr(raw, "headers", None)
    try:
        return headers is not None and any(
            key in headers for key in ("authorization", "Authorization")
        )
    except (TypeError, AttributeError):
        return False


def _linked_channel_refusal(channel, user_id, account_sha256):
    from .personal_identity import CHANNELS, channel_membership_current
    if channel not in CHANNELS or not account_sha256:
        return None
    try:
        if not channel_membership_current(channel, user_id):
            return "Your linked workspace membership is no longer active. Ask your administrator to review access."
    except Exception:
        log.warning("Linked channel membership could not be verified")
        return "Workspace identity policy is unavailable. No task was started; try again later."
    return None
