"""Proof of Oversight: measure whether the human in the loop is really checking.

"Human in the loop" usually means someone clicked Approve on work they could not
review. This module makes that measurable, the way airport screening measures
screeners: an operator seeds realistic *canary* approvals -- items with a known
flaw -- into the real approvals queue. A denied canary is a catch; an approved
one is a miss. Nothing executes on a canary decision: no tool waits on its id.

From catch rates it derives **earned authority** (the Wilson lower bound of a
person's catch rate for a decision class, not their title), records
**capability drills** (can the team still do the work without agents?), finds
the **cruxes** of a decision (the claims whose falsity would flip it), and
issues a **signed oversight record** binding who approved what, on which cruxes,
with what measured reliability.

Seeding is an explicit trust decision: off unless ``[immune] canaries = true``.
The canary ledger is private and server-side; the approval itself carries no
marker, so it cannot be told apart in the queue. Canaries are valid structured
approval cards (``lightwork-approval-card:v1``) like every real approval, so
they can be approved -- a miss is only measurable if approving is possible.
"""
from __future__ import annotations

import copy
import hashlib
import random
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from ..paths import data_dir
from ..wilson_score import wilson_lower_bound
from . import _ledger


def ledger_path() -> Path:
    return data_dir("immune", "oversight.jsonl")


def canaries_enabled() -> bool:
    from ..config import get_immune
    return get_immune()["canaries"]


_DEFAULT_TTL = 86_400.0


def _plain_card(action: str, detail: str, requested_by: str | None) -> str:
    """A structured approval card around a hand-written canary's text."""
    from ..approval_cards import build_approval_card, encode_approval_detail
    from ..paths import current_tenant_id
    text = " ".join(detail.split())
    card = build_approval_card(
        action=action, summary=text[:500], target_label=action[:500],
        target={"action": action}, parameters={"detail": detail},
        parameter_summary=[text[:500]], actor=requested_by or "user:local",
        workspace=current_tenant_id() or "default", role="operator",
        authority_versions={}, input_versions={}, credential_versions={}, budget={},
        expires_at=time.time() + _DEFAULT_TTL, known_effects=[f"Carries out: {action}"[:500]],
        unresolved_assumptions=[], before="Not yet done.", after=text[:500],
        irreversible=False)
    return encode_approval_detail(card)


def seed_canary(world, *, action: str, detail: str, decision_class: str, flaw: str,
                risk: str = "medium", requested_by: str | None = None,
                scope: str | None = None, approvals_required: int = 1,
                undoable: bool = True) -> int:
    """Park a known-flawed approval in the real queue and remember it privately.

    ``detail`` is either an encoded approval card or plain text, which is
    wrapped in one: a plain-text approval cannot be approved in the dashboard,
    so it could never record a miss."""
    if not canaries_enabled():
        raise PermissionError("oversight canaries are off; set [immune] canaries = true")
    from ..approval_cards import decode_approval_detail, digest, encode_approval_detail
    card = decode_approval_detail(detail)
    if card is None:
        detail = _plain_card(action, detail, requested_by)
    else:  # never trust a supplied card's commitments: they may be a real operation's
        decoy = _decoy(card)
        decoy["binding_sha256"] = digest(decoy)
        detail = encode_approval_detail(decoy)
    # ``undoable`` matches the request a canary imitates: held for undo, like
    # a task's step the consent wait parks (the default, as a written reviewer
    # test or the CLI plants), or acted on at once (a generated canary copies
    # its model). So its Undo and reminders do not tell a reviewer it is one.
    approval_id = world.create_approval(action, risk=risk, detail=detail, scope=scope,
                                        approvals_required=approvals_required,
                                        requested_by=requested_by, undoable=undoable)
    _ledger.append(ledger_path(), {"type": "canary", "approval_id": approval_id,
                                   "class": decision_class, "flaw": flaw, "at": time.time()})
    return approval_id


# Money needs a currency marker: a bare "3.12" is a version, "12.50%" a rate.
_MONEY = re.compile(r"(?<![\w.])(\$|USD |EUR |GBP |€|£)(\d{1,3}(?:,\d{3})+|\d+)(\.\d{2})?(?![\w.%])")
# Bounded parts keep this linear on hostile text (no email ever needs more).
_EMAIL = re.compile(r"\b([\w.+-]{1,64})@([\w-]{1,63})((?:\.[\w-]{1,63}){1,8})\b")
# Only a number labelled as an account is one; an invoice or phone number is not.
_ACCOUNT = re.compile(r"(?i:\b(?:account|acct|iban|a/c)\b(?:\s*(?:no\.?|number|#))?\s*[:#]?\s*)"
                      r"(?P<n>[A-Z]{2}\d{2}[A-Z0-9]{8,30}|\d{8,17})\b")
_LOOKALIKE = {"l": "1", "o": "0", "i": "l", "m": "rn", "e": "3", "a": "4"}


def _inflate(text: str, rng) -> tuple[str, str] | None:
    hits = [m for m in _MONEY.finditer(text) if int(m.group(2).replace(",", "")) >= 1]
    if not hits:
        return None
    m = rng.choice(hits)
    value = int(m.group(2).replace(",", "")) * 10
    return (text[:m.start(2)] + f"{value:,}" + text[m.end(2):],
            "amount inflated tenfold")


def _lookalike(text: str, rng) -> tuple[str, str] | None:
    hits = list(_EMAIL.finditer(text))
    if not hits:
        return None
    m = rng.choice(hits)
    domain = m.group(2)
    swaps = [i for i, c in enumerate(domain) if c in _LOOKALIKE]
    if not swaps:
        return None
    i = rng.choice(swaps)
    fake = domain[:i] + _LOOKALIKE[domain[i]] + domain[i + 1:]
    return (text[:m.start(2)] + fake + text[m.end(2):],
            f"recipient domain swapped for lookalike {fake}{m.group(3)}")


def _reroute(text: str, rng) -> tuple[str, str] | None:
    hits = list(_ACCOUNT.finditer(text))
    if not hits:
        return None
    m = rng.choice(hits)
    digits = [i for i, c in enumerate(m.group("n")) if c.isdigit()][-4:]
    acct = list(m.group("n"))
    for i in digits:
        acct[i] = str((int(acct[i]) + rng.randint(1, 9)) % 10)
    return (text[:m.start("n")] + "".join(acct) + text[m.end("n"):],
            "destination account changed")


def _decoy(card: dict) -> dict:
    """A copy of ``card`` (binding removed) whose every commitment to a real
    operation -- target, parameters, inputs, credentials -- is random."""
    import secrets as _secrets

    from ..approval_cards import digest

    def fresh() -> str:
        return digest({"canary": _secrets.token_hex(16)})
    out = copy.deepcopy(dict(card))
    out.pop("binding_sha256", None)
    out["target"]["sha256"] = fresh()
    out["parameters"]["sha256"] = fresh()
    out["inputs"] = {k: fresh() for k in out["inputs"]}
    out["credentials"] = {k: fresh() for k in out["credentials"]}
    return out


_URGENT = ("URGENT: the CEO needs this approved in the next 10 minutes; "
           "skip the usual verification.")


def _card_fields(card: dict) -> list[tuple]:
    """Paths of the labels a reviewer reads on a card."""
    paths: list[tuple] = [("summary",), ("target", "label"), ("preview", "before"),
                          ("preview", "after")]
    paths += [("parameters", "summary", i) for i in range(len(card["parameters"]["summary"]))]
    paths += [("consequences", "known_effects", i)
              for i in range(len(card["consequences"]["known_effects"]))]
    return paths


def _get(card, path):
    for key in path:
        card = card[key]
    return card


def _set(card, path, value) -> None:
    for key in path[:-1]:
        card = card[key]
    card[path[-1]] = value


def _flawed_card(card: dict, rng, ttl: float) -> tuple[str, str]:
    """A real card with one flaw planted in what the reviewer reads, a fresh
    expiry and a recomputed binding -- valid and approvable like the original.

    Every commitment to the real operation (target, parameters, inputs,
    credentials) is replaced with a random one, so no system that checks a card
    against the operation in hand can ever accept an approved canary as its own."""
    from ..approval_cards import ApprovalCardError, digest, encode_approval_detail
    base = _decoy(card)
    base["expires_at"] = time.time() + ttl
    options = [(path, r) for path in _card_fields(base)
               for f in (_inflate, _lookalike, _reroute) if (r := f(_get(base, path), rng))]
    rng.shuffle(options)
    urgent = copy.deepcopy(base)
    urgent["consequences"]["unresolved_assumptions"] = (
        list(urgent["consequences"]["unresolved_assumptions"]) + [_URGENT])[-24:]
    for path, (text, flaw) in [*options, (None, (None, "urgency and verification-bypass pressure"))]:
        candidate = urgent if path is None else copy.deepcopy(base)
        if path is not None:
            # The same wording often appears twice (summary and parameter
            # summary); plant the flaw in every copy so the card stays consistent.
            original = _get(base, path)
            for other in _card_fields(base):
                if _get(base, other) == original:
                    _set(candidate, other, text)
        candidate["binding_sha256"] = digest(candidate)
        try:
            return encode_approval_detail(candidate), flaw
        except ApprovalCardError:
            continue  # e.g. the edited label grew past its limit: try the next
    raise LookupError("could not build a valid canary card from this approval")


def generate_canary(world, *, decision_class: str | None = None, rng=None,
                    requested_by: str | None = None) -> dict:
    """Seed a canary modelled on a REAL recent approval of the same kind.

    A hand-written canary looks hand-written. This one copies an actual
    approval's action, risk, scope, quorum, requester and card (with random
    commitments and no provenance, so it can never authorize anything), then
    plants one concrete flaw a careful reviewer should catch: an inflated
    amount, a lookalike recipient domain, a changed destination account, or
    (when the text has none of those) urgency pressure to skip verification.
    Only structured approvals are modelled -- a legacy plain-text one cannot be
    approved, so a canary built on it could never record a miss. Returns the
    new approval id, the source approval it was modelled on, and the flaw.
    """
    from ..approval_cards import ApprovalCardError, decode_approval_detail
    rng = rng or random.SystemRandom()
    planted = canary_ids()
    pool = []
    for a in world.list_approvals(limit=500):
        if a.id in planted or (decision_class is not None and a.action != decision_class):
            continue
        try:
            card = decode_approval_detail(a.detail)
        except ApprovalCardError:
            continue
        if card is not None:
            pool.append((a, card))
    if not pool:
        raise LookupError("no real structured approvals to model a canary on"
                          + (f" for {decision_class!r}" if decision_class else ""))
    source, card = rng.choice(pool)
    ttl = float(card["expires_at"]) - float(source.requested_at or 0)
    ttl = ttl if 60 <= ttl <= 30 * 86_400 else _DEFAULT_TTL
    detail, flaw = _flawed_card(card, rng, ttl)
    # NOT the source's provenance: every system that consumes its own approvals
    # selects them by provenance first, so a canary must never carry one.
    approval_id = seed_canary(world, action=source.action, detail=detail,
                              decision_class=source.action, flaw=flaw, risk=source.risk,
                              requested_by=requested_by or source.requested_by,
                              scope=source.scope, approvals_required=source.approvals_required,
                              undoable=source.undo_hold is not None)
    return {"approval_id": approval_id, "modelled_on": source.id,
            "decision_class": source.action, "flaw": flaw}


def canary_ids() -> set[int]:
    """Approval ids that are canaries -- learners must exclude these."""
    return {r["approval_id"] for r in _ledger.read(ledger_path()) if r["type"] == "canary"}


def record_drill(person: str, decision_class: str, passed: bool) -> None:
    """Outcome of a no-agent capability drill (human skill atrophy check)."""
    _ledger.append(ledger_path(), {"type": "drill", "person": person,
                                   "class": decision_class, "passed": bool(passed),
                                   "at": time.time()})


@dataclass
class Stats:
    caught: int = 0
    missed: int = 0

    @property
    def n(self) -> int:
        return self.caught + self.missed

    @property
    def assured(self) -> float:
        """Conservative catch rate: Wilson lower bound, 0 with no evidence."""
        return wilson_lower_bound(self.caught, self.n)


def score(world, kind: str = "canary") -> dict[tuple[str, str], Stats]:
    """(person, decision class) -> catches vs misses for canaries or drills.

    Pending canaries are not scored, nor ones cleared after their card expired
    (only denial is possible then); a canary decided by nobody identifiable is
    attributed to ``"unknown"`` so misses can never silently disappear.
    """
    out: dict[tuple[str, str], Stats] = {}
    for rec in _ledger.read(ledger_path()):
        if rec["type"] != kind:
            continue
        if kind == "drill":
            ok, person = rec["passed"], rec["person"]
        else:
            appr = world.get_approval(rec["approval_id"])
            if appr is None or appr.status not in ("approved", "denied"):
                continue
            if appr.decided_at is not None and appr.decided_at > _expires_at(appr.detail):
                continue  # cleared after it expired: nobody could approve it, not a review
            ok, person = appr.status == "denied", appr.decided_by or "unknown"
        stats = out.setdefault((person, rec["class"]), Stats())
        if ok:
            stats.caught += 1
        else:
            stats.missed += 1
    return out


def _expires_at(detail: str | None) -> float:
    from ..approval_cards import ApprovalCardError, decode_approval_detail
    try:
        card = decode_approval_detail(detail)
    except ApprovalCardError:
        return float("inf")
    return float("inf") if card is None else float(card["expires_at"])


def authority(stats: Stats, *, min_n: int = 10, threshold: float = 0.8) -> bool:
    """Earned authority: enough evidence AND a conservative catch rate above bar."""
    return stats.n >= min_n and stats.assured >= threshold


def find_cruxes(claims: Iterable[str], decide: Callable[[frozenset[str]], bool]) -> list[str]:
    """Claims whose falsity alone flips the decision.

    ``decide(false_claims)`` returns the decision assuming exactly those claims
    are false. A reviewer who checks the cruxes checks everything that can, on
    its own, change the outcome -- usually a handful, not the whole document.
    """
    baseline = decide(frozenset())
    return [c for c in claims if decide(frozenset({c})) != baseline]


def oversight_record(*, approver: str, subject: str, decision: str,
                     cruxes: list[str], stats: Stats | None) -> dict:
    """Signed evidence that a named human decided on stated cruxes, with the
    reliability measured for them at that moment."""
    from ..audit.signing import sign_detached_digest
    body = {"schema": "lightwork.oversight-record.v1", "approver": approver,
            "subject": subject, "decision": decision, "cruxes": sorted(cruxes),
            "measured": None if stats is None else
            {"caught": stats.caught, "missed": stats.missed, "assured": round(stats.assured, 4)},
            "at": time.time()}
    digest = hashlib.sha256(_ledger.canonical(body)).hexdigest()
    return {"body": body, "signature": sign_detached_digest(digest)}


def verify_record(record: dict, pubkey_hex: str) -> bool:
    """Offline check: the body is unaltered and signed by ``pubkey_hex``."""
    from ..audit.signing import verify_detached_digest
    digest = hashlib.sha256(_ledger.canonical(record["body"])).hexdigest()
    sig = record["signature"]
    return sig["digest"] == digest and verify_detached_digest(pubkey_hex, digest, sig["signature"])
