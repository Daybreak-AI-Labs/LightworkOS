"""Verified agent-to-agent handoffs: the signed envelope + its verifier.

The **trust layer** for inter-agent delegation. Lightwork already has the two
pieces this sits between:

  * :mod:`maverick.agent_bus` -- the *transport* (in-memory inboxes, ``send``/
    ``recv``), which deliberately does no auth ("just enough plumbing");
  * :mod:`maverick.capability` -- the *grant* (a signed, **attenuating**,
    principal-bound :class:`~maverick.capability.Capability`).

What was missing is the trust frame *between* them: when one agent hands a
sub-task to another, how does the receiver know the request is authentic, scoped,
and not replayed -- and run under exactly the delegated authority, no more? This
module is that frame.

Not to be confused with :mod:`maverick.a2a`, which implements the *external*
Linux-Foundation A2A standard (Agent-Card discovery + the inbound task API,
bearer-auth). That is cross-vendor interop; this is the internal fleet's own
delegation trust. They compose: an external A2A call lands as a principal, then
internal work is delegated between agents via *these* signed handoffs.

The verifier is **pure and offline** (like :mod:`maverick.governance`) so the
trust decision is exhaustively unit-testable; wiring it onto the bus is a
separate step (a handoff Envelope is what rides as an ``agent_bus`` payload).

Trust model, from the proposal:

  * **authenticity** -- the grant is Ed25519-signed by a trusted issuer, and the
    whole envelope is signed by that same issuer (the supervisor mediates the
    handoff). An untrusted/forged signer is rejected; with ``cryptography`` absent
    the verifier **fails closed** ("verified" is meaningless without it).
  * **least privilege** -- the receiver runs under ``grant`` and nothing more
    (confused-deputy safe). Escalation is impossible because the grant was minted
    by *attenuating* the delegator's grant (:meth:`Capability.attenuate`); the
    verifier hands back exactly the grant to run under.
  * **integrity / non-repudiation** -- the signature covers every field, so no
    field can be altered (or a grant swapped in) without breaking it.
  * **freshness** -- a timestamp window plus a single-use nonce defeat replay.

Single-issuer anchoring is the first build; multi-hop lineage chains (a grant's
spawn chain resolving through several supervisors) are a future extension.
"""
from __future__ import annotations

import json
import math
import threading
import time
import uuid
from dataclasses import dataclass, replace

from .audit import signing
from .capability import Capability, sign_capability, verify_capability

INTENTS = ("handoff", "request", "response", "broadcast")

# A signed handoff ultimately becomes model input and occupies an in-memory bus
# slot.  Bound both its serialized frame and its repeated fields before signing
# or verifying so authenticated peers cannot turn a tiny inbox entry into an
# arbitrarily large allocation/scan.
HANDOFF_MAX_ENVELOPE_BYTES = 64 * 1024
HANDOFF_MAX_TEXT_BYTES = 32 * 1024
HANDOFF_MAX_ID_BYTES = 256
HANDOFF_MAX_NONCE_BYTES = 128
HANDOFF_MAX_TOOLS = 128
HANDOFF_MAX_TOOL_BYTES = 256
HANDOFF_MAX_NONCES = 8192
HANDOFF_MAX_AGE_SECONDS = 86_400.0
HANDOFF_MAX_CLOCK_SKEW_SECONDS = 3_600.0


@dataclass(frozen=True)
class Envelope:
    """A signed inter-agent message. ``grant`` is the attenuated capability the
    recipient runs under; ``grant_sig``/``issuer_pub``/``sig`` are the trust frame
    (everything outside them is the work). The three signature fields are ``None``
    until :func:`mint_handoff` signs the envelope."""

    sender: str                 # delegating principal (the "from")
    recipient: str              # receiving principal; the grant is minted FOR it
    task: str                   # human-readable sub-task
    grant: Capability           # the attenuated capability the receiver runs under
    nonce: str
    ts: float
    intent: str = "handoff"
    required_tools: tuple[str, ...] = ()   # tools the task needs; must be in-scope
    body: str = ""
    grant_sig: str | None = None           # issuer signature over the grant
    issuer_pub: str | None = None          # issuing supervisor's pubkey (trust-anchored)
    sig: str | None = None                 # issuer signature over the whole envelope

    def _core(self) -> dict:
        """The fields the envelope signature binds (everything but ``sig``)."""
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "task": self.task,
            "grant": self.grant.signing_bytes().decode("utf-8"),
            "grant_sig": self.grant_sig,
            "issuer_pub": self.issuer_pub,
            "nonce": self.nonce,
            "ts": self.ts,
            "intent": self.intent,
            "required_tools": sorted(self.required_tools),
            "body": self.body,
        }

    def signing_bytes(self) -> bytes:
        """Canonical, stable serialization for signing/verification."""
        return json.dumps(self._core(), sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class HandoffVerdict:
    """Outcome of verifying an :class:`Envelope`. ``rule`` names the check that
    decided, for the audit record. On ``ok`` the ``grant`` is the (attenuated)
    capability the receiver MUST run under -- never its ambient authority."""

    ok: bool
    rule: str
    reason: str
    grant: Capability | None = None


class NonceCache:
    """Single-use nonce tracker (replay defense).

    In-memory and per-process; a live multi-node bus would back this with a
    shared store (the interface is the same). ``seen`` reports prior use;
    :func:`verify_handoff` calls ``remember`` only after a fully-valid handoff."""

    def __init__(self, *, max_entries: int = HANDOFF_MAX_NONCES) -> None:
        try:
            parsed_max = int(max_entries)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("max_entries must be between 1 and 1000000") from exc
        if isinstance(max_entries, bool) or not 1 <= parsed_max <= 1_000_000:
            raise ValueError("max_entries must be between 1 and 1000000")
        self._max_entries = parsed_max
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune_locked(self, now: float) -> None:
        for nonce in [nonce for nonce, expiry in self._seen.items() if expiry <= now]:
            del self._seen[nonce]

    def seen(self, nonce: str, *, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        with self._lock:
            self._prune_locked(current)
            return nonce in self._seen

    def remember(
        self,
        nonce: str,
        *,
        expires_at: float | None = None,
        now: float | None = None,
    ) -> bool:
        """Atomically remember a nonce, refusing rather than evicting live ones.

        Returning ``False`` means either replay or cache saturation.  The caller
        fails the handoff closed in both cases.  Expired entries are pruned so a
        long-running process remains bounded without weakening the freshness
        window's replay guarantee.
        """
        current = time.time() if now is None else now
        expiry = current + 300.0 if expires_at is None else expires_at
        if not math.isfinite(current) or not math.isfinite(expiry) or expiry <= current:
            return False
        with self._lock:
            self._prune_locked(current)
            if nonce in self._seen or len(self._seen) >= self._max_entries:
                return False
            self._seen[nonce] = expiry
            return True


def _utf8_size(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _bounded_tools(required_tools) -> tuple[str, ...]:
    if isinstance(required_tools, str):
        raise ValueError("required_tools must be a collection of tool names")
    try:
        iterator = iter(required_tools)
    except TypeError as exc:
        raise ValueError("required_tools must be a collection of tool names") from exc
    tools: list[str] = []
    for tool in iterator:
        if len(tools) >= HANDOFF_MAX_TOOLS:
            raise ValueError(f"required_tools exceeds {HANDOFF_MAX_TOOLS} entries")
        size = _utf8_size(tool)
        if size is None or not tool or size > HANDOFF_MAX_TOOL_BYTES:
            raise ValueError("required_tools contains an invalid tool name")
        tools.append(tool)
    if len(set(tools)) != len(tools):
        raise ValueError("required_tools contains duplicate tool names")
    return tuple(tools)


def _envelope_structure_error(env: Envelope) -> str | None:
    """Return a bounded structural error without raising on hostile objects."""
    if not isinstance(env, Envelope) or not isinstance(env.grant, Capability):
        return "envelope or grant has the wrong type"
    for name in ("sender", "recipient"):
        size = _utf8_size(getattr(env, name, None))
        if size is None or not getattr(env, name) or size > HANDOFF_MAX_ID_BYTES:
            return f"{name} is invalid or too large"
    for name in ("task", "body"):
        size = _utf8_size(getattr(env, name, None))
        if size is None or size > HANDOFF_MAX_TEXT_BYTES:
            return f"{name} is invalid or too large"
    nonce_size = _utf8_size(env.nonce)
    if nonce_size is None or not env.nonce or nonce_size > HANDOFF_MAX_NONCE_BYTES:
        return "nonce is invalid or too large"
    if not isinstance(env.ts, (int, float)) or isinstance(env.ts, bool):
        return "timestamp is not numeric"
    if not math.isfinite(float(env.ts)):
        return "timestamp is not finite"
    intent_size = _utf8_size(env.intent)
    if intent_size is None or not env.intent or intent_size > 32:
        return "intent is invalid or too large"
    if not isinstance(env.required_tools, tuple):
        return "required_tools must be a tuple"
    try:
        normalized = _bounded_tools(env.required_tools)
    except ValueError as exc:
        return str(exc)
    if normalized != env.required_tools:
        return "required_tools is not canonical"
    expiry = env.grant.expires_at
    if expiry is not None and (
        isinstance(expiry, bool)
        or not isinstance(expiry, (int, float))
        or not math.isfinite(float(expiry))
    ):
        return "grant expiry is invalid"
    for name in ("grant_sig", "issuer_pub", "sig"):
        value = getattr(env, name)
        if value is not None:
            size = _utf8_size(value)
            if size is None or size > 256:
                return f"{name} is invalid or too large"
    try:
        size = len(env.signing_bytes())
    except (TypeError, ValueError, UnicodeError, OverflowError):
        return "envelope cannot be canonically serialized"
    if size > HANDOFF_MAX_ENVELOPE_BYTES:
        return f"envelope exceeds {HANDOFF_MAX_ENVELOPE_BYTES} bytes"
    return None


def _freshness_bounds(
    now: object, max_age_s: object, clock_skew_s: object,
) -> tuple[float, float, float] | None:
    """Normalize caller-provided freshness values, or reject them safely."""
    try:
        age = float(max_age_s)
        skew = float(clock_skew_s)
        current = float(now)
    except (TypeError, ValueError, OverflowError):
        return None
    if isinstance(max_age_s, bool) or isinstance(clock_skew_s, bool):
        return None
    if not all(math.isfinite(value) for value in (age, skew, current)):
        return None
    if not 0 < age <= HANDOFF_MAX_AGE_SECONDS:
        return None
    if not 0 <= skew <= HANDOFF_MAX_CLOCK_SKEW_SECONDS:
        return None
    return current, age, skew


def _trusted_issuer_set(trusted_issuers) -> set | None:
    try:
        return set(trusted_issuers)
    except (TypeError, ValueError):
        return None


def _out_of_scope_tool(env: Envelope, now: float) -> str | None:
    for tool in env.required_tools:
        if not env.grant.permits(tool, now=now):
            return tool
    return None


def _sign_ed25519(private_hex: str, data: bytes) -> str:
    """Ed25519-sign ``data``; hex signature. Mirrors :func:`capability.sign_capability`."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    return priv.sign(data).hex()


def mint_handoff(
    *,
    sender: str,
    recipient: str,
    task: str,
    grant: Capability,
    issuer_private_hex: str,
    issuer_pub_hex: str,
    intent: str = "handoff",
    required_tools=(),
    body: str = "",
    nonce: str | None = None,
    ts: float | None = None,
) -> Envelope:
    """Mint a signed handoff: the issuer (supervisor) signs both the attenuated
    ``grant`` and the whole envelope.

    ``grant.principal`` MUST equal ``recipient`` -- the grant is minted *for* the
    receiver, who runs under it. The grant must already be an attenuation of the
    delegator's grant (that is what makes escalation impossible); this function
    broadens nothing. Requires ``cryptography``.
    """
    if grant.principal != recipient:
        raise ValueError(
            "grant.principal must equal recipient (the grant is minted for the receiver)"
        )
    if intent not in INTENTS:
        raise ValueError(f"unknown intent {intent!r}; expected one of {INTENTS}")
    required_tools = _bounded_tools(required_tools)
    nonce = nonce or uuid.uuid4().hex
    ts = time.time() if ts is None else ts
    env = Envelope(
        sender=sender,
        recipient=recipient,
        task=task,
        grant=grant,
        nonce=nonce,
        ts=ts,
        intent=intent,
        required_tools=required_tools,
        body=body,
        grant_sig=None,
        issuer_pub=issuer_pub_hex,
    )
    structure_error = _envelope_structure_error(env)
    if structure_error is not None:
        raise ValueError(f"invalid handoff: {structure_error}")
    grant_sig = sign_capability(grant, issuer_private_hex)
    env = replace(env, grant_sig=grant_sig)
    structure_error = _envelope_structure_error(env)
    if structure_error is not None:  # signature fields count toward the frame bound
        raise ValueError(f"invalid handoff: {structure_error}")
    return replace(env, sig=_sign_ed25519(issuer_private_hex, env.signing_bytes()))


def verify_handoff(
    env: Envelope,
    *,
    trusted_issuers,
    nonce_cache: NonceCache | None = None,
    now: float | None = None,
    max_age_s: float = 300.0,
    clock_skew_s: float = 60.0,
    expected_recipient: str | None = None,
    expected_sender: str | None = None,
) -> HandoffVerdict:
    """Verify a handoff envelope. Returns a :class:`HandoffVerdict`; never raises.

    Checks, strictest/clearest first:
      0. crypto present (else fail closed -- "verified" is meaningless without it);
      1. structurally signed (issuer_pub + grant_sig + sig present);
      2. issuer is a **trusted** supervisor key;
      3. the **grant** is authentically signed by that issuer;
      4. the **envelope** is signed by that issuer (no field/grant tampered);
      5. the signed recipient is the actual receiving inbox and the signed
         sender matches the transport wrapper (when supplied by the binding);
      6. the grant is bound to *this* recipient (no grant swap);
      7. intent is known;
      8. **fresh** -- not future-dated past the skew, not older than the window;
      9. **not replayed** -- the nonce is unused;
      10. **in scope** -- the grant is unexpired and permits every required tool.

    On success the verdict carries the grant the receiver must run under.
    """
    now = time.time() if now is None else now

    if not signing._have_crypto():
        return HandoffVerdict(False, "no_crypto", "cryptography unavailable; cannot verify")
    structure_error = _envelope_structure_error(env)
    if structure_error is not None:
        return HandoffVerdict(False, "malformed", structure_error)
    freshness = _freshness_bounds(now, max_age_s, clock_skew_s)
    if freshness is None:
        return HandoffVerdict(False, "bad_freshness_window", "freshness bounds are invalid")
    now, max_age_s, clock_skew_s = freshness
    if not (env.sig and env.grant_sig and env.issuer_pub):
        return HandoffVerdict(False, "unsigned", "missing issuer_pub / grant_sig / sig")
    trusted = _trusted_issuer_set(trusted_issuers)
    if trusted is None:
        return HandoffVerdict(False, "untrusted_issuer", "trusted issuer set is invalid")
    if env.issuer_pub not in trusted:
        return HandoffVerdict(False, "untrusted_issuer",
                              f"issuer {env.issuer_pub[:16]}... is not a trusted supervisor")
    if not verify_capability(env.grant, env.grant_sig, env.issuer_pub):
        return HandoffVerdict(False, "bad_grant_sig", "the grant's signature does not verify")
    if not signing.verify_ed25519(env.issuer_pub, env.sig, env.signing_bytes()):
        return HandoffVerdict(False, "tampered", "the envelope signature does not verify")
    if expected_recipient is not None and env.recipient != expected_recipient:
        return HandoffVerdict(
            False,
            "recipient_mismatch",
            f"handoff is for {env.recipient!r}, not inbox {expected_recipient!r}",
        )
    if expected_sender is not None and env.sender != expected_sender:
        return HandoffVerdict(
            False,
            "sender_mismatch",
            f"signed sender {env.sender!r} does not match delivery wrapper",
        )
    if env.grant.principal != env.recipient:
        return HandoffVerdict(False, "grant_recipient_mismatch",
                              f"grant is for {env.grant.principal!r}, not recipient {env.recipient!r}")
    if env.intent not in INTENTS:
        return HandoffVerdict(False, "bad_intent", f"unknown intent {env.intent!r}")
    if env.ts > now + clock_skew_s:
        return HandoffVerdict(False, "future_ts", "timestamp is in the future")
    if now - env.ts > max_age_s:
        return HandoffVerdict(False, "stale", f"older than the {max_age_s:.0f}s window")
    if nonce_cache is not None and nonce_cache.seen(env.nonce, now=now):
        return HandoffVerdict(False, "replay", "nonce has already been used")
    if env.grant.is_expired(now):
        return HandoffVerdict(False, "grant_expired", "the delegated grant has expired")
    denied_tool = _out_of_scope_tool(env, now)
    if denied_tool is not None:
        return HandoffVerdict(
            False,
            "out_of_scope",
            f"grant does not permit required tool {denied_tool!r}",
        )

    if nonce_cache is not None and not nonce_cache.remember(
        env.nonce,
        expires_at=float(env.ts) + max_age_s,
        now=now,
    ):
        # A same-nonce race is a replay; a full cache is safe saturation.  Do
        # not evict an unexpired nonce, because that would reopen its replay
        # window merely because a peer sent enough otherwise-valid traffic.
        if nonce_cache.seen(env.nonce, now=now):
            return HandoffVerdict(False, "replay", "nonce has already been used")
        return HandoffVerdict(False, "nonce_cache_full", "replay cache is full")
    return HandoffVerdict(True, "ok", "handoff verified", grant=env.grant)


__all__ = [
    "Envelope",
    "HandoffVerdict",
    "NonceCache",
    "mint_handoff",
    "verify_handoff",
    "INTENTS",
    "HANDOFF_MAX_ENVELOPE_BYTES",
    "HANDOFF_MAX_TEXT_BYTES",
    "HANDOFF_MAX_TOOLS",
    "HANDOFF_MAX_TOOL_BYTES",
]
