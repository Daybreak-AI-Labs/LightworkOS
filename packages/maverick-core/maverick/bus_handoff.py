"""Verified handoffs over the cross-agent bus.

:mod:`maverick.agent_bus` delivers arbitrary payloads with no auth;
:mod:`maverick.handoff` is the signed, *attenuating* delegation envelope + its
verifier. This module bridges them: a delegation rides the bus as an
:class:`~maverick.handoff.Envelope`, minted + signed by the run's
:class:`HandoffAuthority` and verified on receipt -- so a peer-to-peer handoff
actually carries scoped authority the receiver can trust (routing, sender,
replay, tamper, expiry, and out-of-scope all rejected), the trust frame the bare
bus lacks.

Trust model. In-process the bus is a single trust domain, so the authority is a
per-run **ephemeral Ed25519 issuer**: the orchestrator is the trust root, mints
(signs) every handoff, and is the sole trusted issuer -- a delegation that didn't
originate in this run is rejected. The value is real even in-process (it rejects
stale/forged/out-of-scope delegations and is the exact seam a *multi-node* bus
slots a durable issuer into), but it is not a defense against code already running
inside the process with ``SwarmContext`` access. Capability enforcement being
off leaves this optional layer disabled. Once enforcement is on, however, a
delegation fails **closed** if signing authority is unavailable; callers must
use the explicitly untrusted plain-message tool instead of silently downgrading.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from . import agent_bus
from .capability import Capability
from .handoff import Envelope, HandoffVerdict, NonceCache, mint_handoff, verify_handoff


def _new_issuer_keypair() -> tuple[str, str]:
    """A fresh Ed25519 ``(private_hex, public_hex)``. Requires ``cryptography``."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return priv_hex, pub_hex


@dataclass
class HandoffAuthority:
    """A run's handoff trust domain: the issuer key + a single-use nonce cache.

    The orchestrator is the trust root -- it mints (signs) every handoff and is
    the sole trusted issuer, so a delegation not minted here is rejected. One per
    run, shared via ``SwarmContext`` so the nonce cache (replay defense) is
    process-wide. ``verify`` is locked because the bus runs agents concurrently
    and ``NonceCache``'s seen/remember is not atomic.
    """

    issuer_private_hex: str
    issuer_pub_hex: str
    nonce_cache: NonceCache = field(default_factory=NonceCache)
    max_age_s: float = 300.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def for_run(cls) -> HandoffAuthority:
        """Mint an ephemeral issuer for a run. Requires ``cryptography``."""
        priv, pub = _new_issuer_keypair()
        return cls(issuer_private_hex=priv, issuer_pub_hex=pub)

    def mint(
        self,
        *,
        sender: str,
        recipient: str,
        grant: Capability,
        task: str,
        required_tools=(),
        body: str = "",
    ) -> Envelope:
        """Sign a handoff delegating ``grant`` (minted for ``recipient``) to a peer."""
        return mint_handoff(
            sender=sender,
            recipient=recipient,
            task=task,
            grant=grant,
            issuer_private_hex=self.issuer_private_hex,
            issuer_pub_hex=self.issuer_pub_hex,
            required_tools=required_tools,
            body=body,
        )

    def verify(
        self,
        env: Envelope,
        *,
        now: float | None = None,
        expected_recipient: str | None = None,
        expected_sender: str | None = None,
    ) -> HandoffVerdict:
        """Verify a handoff against this run's issuer + nonce cache (replay-safe)."""
        with self._lock:
            return verify_handoff(
                env,
                trusted_issuers={self.issuer_pub_hex},
                nonce_cache=self.nonce_cache,
                now=now,
                max_age_s=self.max_age_s,
                expected_recipient=expected_recipient,
                expected_sender=expected_sender,
            )


@dataclass(frozen=True)
class HandoffDelivery:
    """What :func:`receive_handoff` returns. For a verified handoff, ``grant`` is
    the attenuated capability the receiver runs the task under; a non-handoff
    payload comes back with ``verdict=None`` (unverified info, like a plain
    message)."""

    sender: str
    payload: Any            # the Envelope (handoff) or the raw payload (plain message)
    verdict: HandoffVerdict | None

    @property
    def is_handoff(self) -> bool:
        return self.verdict is not None

    @property
    def ok(self) -> bool:
        return self.verdict is not None and self.verdict.ok

    @property
    def grant(self) -> Capability | None:
        return self.verdict.grant if self.verdict is not None else None


def authority_for(ctx: Any) -> HandoffAuthority | None:
    """Get-or-create the run's :class:`HandoffAuthority`.

    Installed only when ``cryptography`` is present AND capability enforcement is
    on -- handoff *verification* is meaningful exactly when the operator has opted
    into capability enforcement. Otherwise returns ``None``. A signed-delegation
    caller must treat ``None`` as unavailable, never silently downgrade to plain
    traffic. Idempotent + locked: all agents in a run share one authority (one
    issuer, one nonce cache).
    """
    existing = getattr(ctx, "handoff_authority", None)
    if existing is not None:
        return existing
    try:
        from .capability import capability_enforced
        from .handoff import signing

        if not (signing._have_crypto() and capability_enforced()):
            return None
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        # A broken/partial crypto backend can *panic* (not ImportError). Report
        # authority unavailable; signed-delegation callers fail closed.
        return None
    lock = getattr(ctx, "_handoff_lock", None)
    if lock is None:
        lock = threading.Lock()
        try:
            ctx._handoff_lock = lock
        except Exception:
            return HandoffAuthority.for_run()  # ctx not mutable; unshared fallback
    with lock:
        existing = getattr(ctx, "handoff_authority", None)
        if existing is None:
            existing = HandoffAuthority.for_run()
            ctx.handoff_authority = existing
    return existing


def send_handoff(
    authority: HandoffAuthority,
    *,
    sender: str,
    recipient: str,
    grant: Capability,
    task: str,
    required_tools=(),
    body: str = "",
    goal_id: int | None = None,
    namespace: str | None = None,
) -> str:
    """Mint a signed handoff and deliver it to ``recipient``'s bus inbox.

    ``grant`` is the attenuated capability the recipient will run under; its
    principal must be ``recipient`` (``mint_handoff`` enforces this). Returns the
    envelope nonce (a delivery id); raises if the recipient's inbox is full.
    """
    env = authority.mint(
        sender=sender, recipient=recipient, grant=grant, task=task,
        required_tools=required_tools, body=body,
    )
    if not agent_bus.send(
        sender,
        recipient,
        env,
        correlation_id=env.nonce,
        goal_id=goal_id,
        namespace=namespace,
    ):
        raise RuntimeError(f"bus inbox full for {recipient!r}; handoff not delivered")
    return env.nonce


def receive_handoff(
    authority: HandoffAuthority | None,
    agent_id: str,
    *,
    timeout: float = 0.0,
    now: float | None = None,
    namespace: str | None = None,
) -> HandoffDelivery | None:
    """Pull one bus message; if it's a handoff envelope, verify it.

    Returns ``None`` when the inbox is empty. For a handoff the verdict says
    whether the receiver may proceed (and under which grant); a non-handoff
    payload returns with ``verdict=None`` (unverified, like a plain message).
    """
    recv_kwargs = {"timeout": timeout}
    if namespace is not None:
        recv_kwargs["namespace"] = namespace
    msg = agent_bus.recv(agent_id, **recv_kwargs)
    if msg is None:
        return None
    if isinstance(msg.payload, Envelope):
        if msg.recipient != agent_id:
            verdict = HandoffVerdict(
                False,
                "delivery_recipient_mismatch",
                "delivery wrapper does not match the receiving inbox",
            )
        elif authority is None:
            verdict = HandoffVerdict(
                False, "no_authority", "no handoff authority installed for this run"
            )
        else:
            verdict = authority.verify(
                msg.payload,
                now=now,
                expected_recipient=agent_id,
                expected_sender=msg.sender,
            )
        return HandoffDelivery(sender=msg.sender, payload=msg.payload, verdict=verdict)
    return HandoffDelivery(sender=msg.sender, payload=msg.payload, verdict=None)


__all__ = [
    "HandoffAuthority",
    "HandoffDelivery",
    "authority_for",
    "send_handoff",
    "receive_handoff",
]
