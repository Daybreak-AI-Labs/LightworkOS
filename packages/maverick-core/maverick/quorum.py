"""Quorum approval for config changes.

The two-person rule already exists for *actions*
(:mod:`maverick.tools.two_person_rule` validates collected sign-offs on an
irreversible op). But the cheaper way to defeat every gate at once is to
edit the *configuration* that defines the gates: raise ``budget.max_dollars``,
blank out ``[governance]``, point ``[plugins]`` at attacker code. One
compromised (or fat-fingered) admin session shouldn't be able to do that
alone — protected keys need N **distinct** approvers before a change applies.

Pieces:

* :class:`QuorumPolicy` — how many approvers (``required``, default 2) and
  which keys are protected (fnmatch globs; default
  ``safety.* / governance.* / budget.max_dollars / plugins.*`` — the keys
  whose mutation defeats other controls).
* :func:`propose` / :func:`approve` / :func:`status` — the proposal ledger,
  persisted atomically (tmp + ``os.replace``, 0600) to
  ``data_dir("config_proposals.json")``. Separation of duties is enforced the
  same way ``two_person_rule`` does: the proposer's own approval is refused,
  and so is a duplicate approver. Every event carries a timestamp.
* :func:`apply_gate` — the question the config-write path asks: "may this
  key change **without** a quorum?" True for unprotected keys; a protected
  key answers False and the writer must hold an ``approved`` proposal
  (``status(change_id) == "approved"``) before applying.
* :func:`prune` — proposals go stale (default ``ttl_days=7``): an approval
  collected against last week's diff shouldn't authorize today's apply.
  ``status`` reports ``"expired"`` for stale proposals; ``prune`` deletes
  them. The clock is injectable so expiry is unit-testable.

Opt-in and default-OFF in effect: the dashboard's settings save flow
(``maverick_dashboard.settings_quorum``) consults :func:`configured_policy`,
which is None until an operator sets a quorum of 2 or more; then a save that
touches a protected setting becomes an approval request (the dashboard's
Approvals, N distinct approvers, never the requester) and applies only once
approved. ``policy_from_config()`` reads ``[safety]
quorum_required`` / ``quorum_protected_keys`` (env
``MAVERICK_QUORUM_REQUIRED`` wins for the count), fail-soft. Stdlib-only.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    ensure_private_directory,
    ensure_private_file,
)
from .paths import data_dir

log = logging.getLogger(__name__)

DEFAULT_REQUIRED = 2
DEFAULT_TTL_DAYS = 7.0
# A settings approval request (approval card) can be voted on for at most 7
# days, so a longer approval lifetime would promise what can't be delivered.
MAX_TTL_DAYS = 7.0
DEFAULT_PROTECTED_KEYS = frozenset({
    "safety.*",
    "governance.*",
    "budget.max_dollars",
    "plugins.*",
})
# The quorum's own settings ([safety] quorum_*): always protected, whatever
# ``protected_keys`` lists, so one person can never switch the approvals off,
# narrow what they cover or stretch how long they last.
SELF_PROTECTED_KEYS = frozenset({"safety.quorum_*"})
# Settings that widen every agent's reach at once: always protected whatever
# ``protected_keys`` lists. [tools] fetch_allow_private turns each prompt-
# injectable URL tool into an intranet client in one save.
GUARD_PROTECTED_KEYS = frozenset({"tools.fetch_allow_private"})

PENDING = "pending"
APPROVED = "approved"
EXPIRED = "expired"

# One lock around every load-modify-save: two concurrent approvals must
# accumulate, not clobber each other (mirrors quotas.UsageLedger).
_STORE_LOCK = threading.Lock()


class QuorumError(ValueError):
    """A proposal/approval was refused (self-approval, duplicate, unknown id)."""


@dataclass(frozen=True)
class QuorumPolicy:
    """How much agreement a protected config change needs."""

    required: int = DEFAULT_REQUIRED
    protected_keys: frozenset[str] = DEFAULT_PROTECTED_KEYS
    ttl_days: float = DEFAULT_TTL_DAYS


@dataclass(frozen=True)
class Proposal:
    """One proposed config change and its collected approvals.

    ``required`` is snapshotted at propose time so a policy edit mid-flight
    can't retroactively shrink the quorum a pending change needs.
    """

    change_id: str
    key: str
    old: object
    new: object
    proposer: str
    proposed_at: float
    required: int
    approvals: tuple[tuple[str, float], ...] = ()  # (approver, approved_at)

    def approved(self) -> bool:
        return len(self.approvals) >= self.required


def is_protected(key: str, policy: QuorumPolicy) -> bool:
    """True iff ``key`` matches any protected pattern (fnmatch, case-sensitive).

    The quorum's own settings (:data:`SELF_PROTECTED_KEYS`) and the reach
    guards (:data:`GUARD_PROTECTED_KEYS`) always are."""
    return any(fnmatchcase(key, pat)
               for pat in (*policy.protected_keys, *SELF_PROTECTED_KEYS,
                           *GUARD_PROTECTED_KEYS))


def apply_gate(key: str, *, policy: QuorumPolicy) -> bool:
    """May ``key`` change **without** a quorum?

    The config-write path consults this before applying a change: ``True``
    means write freely; ``False`` means the writer must hold an approved
    proposal for the change (check ``status(change_id) == APPROVED``).
    """
    return not is_protected(key, policy)


def policy_from_config() -> QuorumPolicy:
    """Build the policy from ``[safety]`` (fail-soft; defaults intact).

    ``quorum_required`` (env ``MAVERICK_QUORUM_REQUIRED`` wins) is clamped to
    >= 1; ``quorum_protected_keys`` *replaces* the default pattern set when
    given (an operator who configures it is taking ownership of the list);
    ``quorum_ttl_days`` bounds proposal freshness.
    """
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("safety") or {}
    except Exception:
        cfg = {}
    required = DEFAULT_REQUIRED
    try:
        required = max(1, int(cfg.get("quorum_required", DEFAULT_REQUIRED)))
    except (TypeError, ValueError):
        pass
    env = os.environ.get("MAVERICK_QUORUM_REQUIRED", "").strip()
    if env:
        try:
            required = max(1, int(env))
        except ValueError:
            pass
    protected = DEFAULT_PROTECTED_KEYS
    raw = cfg.get("quorum_protected_keys")
    if isinstance(raw, (list, tuple, set)):
        cleaned = frozenset(str(p).strip() for p in raw if str(p).strip())
        if cleaned:
            protected = cleaned
    ttl = DEFAULT_TTL_DAYS
    try:
        ttl = float(cfg.get("quorum_ttl_days", DEFAULT_TTL_DAYS))
        if ttl <= 0:
            ttl = DEFAULT_TTL_DAYS
    except (TypeError, ValueError):
        ttl = DEFAULT_TTL_DAYS
    if ttl > MAX_TTL_DAYS:
        log.warning("[safety] quorum_ttl_days=%s is above the %s-day approval window; "
                    "using %s days", ttl, MAX_TTL_DAYS, MAX_TTL_DAYS)
        ttl = MAX_TTL_DAYS
    return QuorumPolicy(required=required, protected_keys=protected, ttl_days=ttl)


def configured_policy() -> QuorumPolicy | None:
    """The policy the settings save flow enforces, or None when it is off.

    On only when an operator set a quorum (``MAVERICK_QUORUM_REQUIRED`` or
    ``[safety] quorum_required``) of at least 2: one approver who could be
    the person asking adds nothing, and an unset quorum keeps today's
    behaviour (a protected setting saves at once).
    """
    raw: object = os.environ.get("MAVERICK_QUORUM_REQUIRED", "").strip() or None
    if raw is None:
        try:
            from .config import load_config
            raw = ((load_config() or {}).get("safety") or {}).get("quorum_required")
        except Exception:
            return None
    if raw is None or isinstance(raw, bool) or not str(raw).strip():
        return None
    policy = policy_from_config()
    return policy if policy.required >= 2 else None


def _default_path() -> Path:
    return data_dir("config_proposals.json")


@dataclass
class ProposalStore:
    """The persistent proposal ledger (``data_dir("config_proposals.json")``).

    Not a hot path, so every operation reloads from disk and saves atomically
    (unique temp file + ``os.replace``, 0600) under one process-wide lock —
    concurrent approvals accumulate instead of last-writer-wins.
    """

    path: Path = field(default_factory=_default_path)
    clock: Callable[[], float] = time.time

    def _load(self) -> dict:
        try:
            ensure_private_directory(self.path.parent)
            ensure_private_file(self.path, 0o600)
            raw = json.loads(atomic_read_text(self.path))
            return raw if isinstance(raw, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            log.warning("quorum: cannot read proposal store %s: %s", self.path, e)
            return {}

    def _save(self, data: dict) -> None:
        ensure_private_directory(self.path.parent)
        atomic_write_text(self.path, json.dumps(data), mode=0o600)

    @staticmethod
    def _to_proposal(rec: dict) -> Proposal:
        return Proposal(
            change_id=str(rec["change_id"]),
            key=str(rec["key"]),
            old=rec.get("old"),
            new=rec.get("new"),
            proposer=str(rec["proposer"]),
            proposed_at=float(rec["proposed_at"]),
            required=int(rec["required"]),
            approvals=tuple((str(a), float(t)) for a, t in rec.get("approvals", [])),
        )

    @staticmethod
    def _to_record(p: Proposal) -> dict:
        return {
            "change_id": p.change_id, "key": p.key, "old": p.old, "new": p.new,
            "proposer": p.proposer, "proposed_at": p.proposed_at,
            "required": p.required, "approvals": [list(a) for a in p.approvals],
        }

    def get(self, change_id: str) -> Proposal | None:
        rec = self._load().get(change_id)
        return self._to_proposal(rec) if isinstance(rec, dict) else None

    def put(self, proposal: Proposal) -> None:
        with _STORE_LOCK:
            data = self._load()
            data[proposal.change_id] = self._to_record(proposal)
            self._save(data)

    def modify(
        self, change_id: str, mutate: Callable[[Proposal], Proposal],
    ) -> Proposal:
        """Atomic read-modify-write of one proposal under ``_STORE_LOCK``.

        ``mutate`` receives the freshly-loaded proposal and returns the updated
        one; both the load and the save happen inside the lock so two concurrent
        approvals accumulate instead of last-writer-wins clobbering each other.
        """
        with _STORE_LOCK:
            data = self._load()
            rec = data.get(change_id)
            if not isinstance(rec, dict):
                raise QuorumError(f"unknown proposal {change_id!r}")
            updated = mutate(self._to_proposal(rec))
            data[updated.change_id] = self._to_record(updated)
            self._save(data)
            return updated

    def all(self) -> list[Proposal]:
        return [self._to_proposal(r) for r in self._load().values()
                if isinstance(r, dict)]

    def delete(self, change_ids) -> None:
        with _STORE_LOCK:
            data = self._load()
            for cid in change_ids:
                data.pop(cid, None)
            self._save(data)


def _is_expired(proposal: Proposal, policy: QuorumPolicy, now: float) -> bool:
    return now - proposal.proposed_at > policy.ttl_days * 86400.0


def propose(
    change_id: str,
    key: str,
    old: object,
    new: object,
    proposer: str,
    *,
    policy: QuorumPolicy | None = None,
    store: ProposalStore | None = None,
) -> Proposal:
    """Open a proposal for changing ``key`` from ``old`` to ``new``.

    Refuses a blank proposer and a duplicate ``change_id`` (an existing
    proposal must not be silently replaced — that would reset nothing while
    looking like a fresh start; withdraw via :meth:`ProposalStore.delete`).
    """
    policy = policy or policy_from_config()
    store = store or ProposalStore()
    proposer = str(proposer or "").strip()
    if not proposer:
        raise QuorumError("a proposal needs a named proposer")
    if store.get(change_id) is not None:
        raise QuorumError(f"proposal {change_id!r} already exists")
    proposal = Proposal(
        change_id=str(change_id),
        key=str(key),
        old=old,
        new=new,
        proposer=proposer,
        proposed_at=float(store.clock()),
        required=policy.required,
    )
    store.put(proposal)
    return proposal


def approve(
    change_id: str,
    approver: str,
    *,
    store: ProposalStore | None = None,
    policy: QuorumPolicy | None = None,
) -> Proposal:
    """Record one approval; returns the updated proposal.

    Separation of duties: the proposer cannot approve their own change, and
    one approver counts once (comparison is case-insensitive on the trimmed
    name, matching ``two_person_rule``). An expired proposal cannot collect
    approvals — stale diffs need a fresh proposal.
    """
    store = store or ProposalStore()
    policy = policy or policy_from_config()
    who = str(approver or "").strip()
    if not who:
        raise QuorumError("an approval needs a named approver")

    # The whole load-validate-rebuild-save must be atomic: reading the proposal
    # outside the lock and rebuilding it with only our own approval lets two
    # concurrent approves last-writer-wins and lose an approval. Run the get +
    # duplicate/self checks + append inside ProposalStore.modify's lock so the
    # approvals accumulate as the store docstring promises.
    def _add_approval(proposal: Proposal) -> Proposal:
        if _is_expired(proposal, policy, float(store.clock())):
            raise QuorumError(f"proposal {change_id!r} has expired; re-propose it")
        if who.lower() == proposal.proposer.lower():
            raise QuorumError("separation of duties: the proposer cannot approve "
                              "their own change")
        if any(a.lower() == who.lower() for a, _ in proposal.approvals):
            raise QuorumError(f"{who!r} has already approved {change_id!r}")
        return Proposal(
            change_id=proposal.change_id, key=proposal.key, old=proposal.old,
            new=proposal.new, proposer=proposal.proposer,
            proposed_at=proposal.proposed_at, required=proposal.required,
            approvals=proposal.approvals + ((who, float(store.clock())),),
        )

    return store.modify(change_id, _add_approval)


def status(
    change_id: str,
    *,
    store: ProposalStore | None = None,
    policy: QuorumPolicy | None = None,
) -> str:
    """``"pending"`` / ``"approved"`` / ``"expired"`` for a proposal.

    Raises :class:`QuorumError` for an unknown id — "no such proposal" must
    not read as "pending" to a config writer.
    """
    store = store or ProposalStore()
    policy = policy or policy_from_config()
    proposal = store.get(change_id)
    if proposal is None:
        raise QuorumError(f"unknown proposal {change_id!r}")
    if _is_expired(proposal, policy, float(store.clock())):
        return EXPIRED
    if proposal.approved():
        return APPROVED
    return PENDING


def prune(
    *,
    store: ProposalStore | None = None,
    policy: QuorumPolicy | None = None,
) -> int:
    """Delete expired proposals; returns how many were removed.

    Approved-but-stale proposals expire too: an approval is consent to a
    change *now*, not a standing authorization.
    """
    store = store or ProposalStore()
    policy = policy or policy_from_config()
    now = float(store.clock())
    stale = [p.change_id for p in store.all() if _is_expired(p, policy, now)]
    if stale:
        store.delete(stale)
    return len(stale)


__all__ = [
    "QuorumPolicy", "Proposal", "ProposalStore", "QuorumError",
    "DEFAULT_PROTECTED_KEYS", "DEFAULT_REQUIRED", "DEFAULT_TTL_DAYS", "MAX_TTL_DAYS",
    "SELF_PROTECTED_KEYS",
    "PENDING", "APPROVED", "EXPIRED",
    "propose", "approve", "status", "prune",
    "is_protected", "apply_gate", "policy_from_config", "configured_policy",
]
