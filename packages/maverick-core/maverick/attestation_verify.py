"""Third-party verifier for a Lightwork attestation bundle.

**This module imports nothing from maverick.** Standard library plus
``cryptography``, deliberately, because that is the whole point: an auditor,
regulator, insurer or acquirer who trusts *neither the operator nor the model
vendor* must be able to check the bundle without installing our platform,
reaching our infrastructure, or asking anyone's permission. ``maverick attest
export-verifier`` copies this exact file, and it runs on its own::

    python attestation_verify.py bundle.json --key <publisher-pubkey-hex>
    python attestation_verify.py bundle.json --key <hex> --evidence ~/.maverick/audit

Two things this verifier will not do, both load-bearing:

*It will not take the bundle's word for who signed it.* The signing key must
arrive out of band -- from the publisher's key page, a contract, a prior
engagement -- and the key embedded in the bundle must match it. Verifying a
signature against a key carried *inside* the signed artifact proves only that
the file has not been edited since somebody signed it; the somebody is
unconstrained. That is integrity, not provenance, and provenance is what a
third party came for. Without ``--key`` verification fails closed.

*It will not upgrade an unchecked claim into a passing one.* Each claim reports
``HOLDS`` / ``FAILS`` / ``INDETERMINATE`` / ``NOT_APPLICABLE``, and the last two
are not softer synonyms for the first. A deployment with an empty policy
envelope has no violations to find, but "nothing was forbidden, so nothing was
violated" is not a compliance finding and is never reported as one. An
encrypted-at-rest audit segment cannot be re-walked without the tenant's key, so
its history is ``INDETERMINATE`` here even though the issuer could verify it
in-house -- "the publisher checked it" is precisely the assurance this tool
exists to replace.

What ``HOLDS`` on the history claim does and does not mean: the signed rows
present are internally consistent, each row's hash covers its content, each
signature verifies under the trusted key, and the digests, tips and row counts
**the bundle committed to** still match the files -- so a removed row, an edited
row, or a deleted day-file is detectable. Note what that does not include: this
verifier never reads the issuer's anchor ledger. The anchors block travels in the
bundle because it is part of what was signed, but every check here is against the
bundle's own commitments, and a claim to have cross-checked an external ledger
would be an overclaim. It is also not a proof that nothing happened outside the
chain. No artifact can prove that; a verifier that implied otherwise would be
worse than none.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA_VERSION = 1
BUNDLE_KIND = "maverick-attestation"

HOLDS = "HOLDS"
FAILS = "FAILS"
INDETERMINATE = "INDETERMINATE"
NOT_APPLICABLE = "NOT_APPLICABLE"

#: Depth reached by a verification run, weakest first.
DEPTH_NONE = "unverified"
DEPTH_SIGNED = "signed"
DEPTH_CORROBORATED = "corroborated"

# The three gradings a promotion receipt may carry (mirrors
# maverick.self_improvement). An unrecognised value is a failure, not a
# downgrade: a writer who invents a stronger-sounding label must not have it
# quietly accepted as a weaker one.
_PROBED_BOUNDED = "probed_bounded"
_DECLARED_BOUNDED = "declared_bounded"
_UNPROVEN = "unproven"
_KNOWN_GRADINGS = (_PROBED_BOUNDED, _DECLARED_BOUNDED, _UNPROVEN)

_RISK_ORDER = ("low", "medium", "high")


@dataclass
class ClaimResult:
    name: str
    status: str
    detail: str
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Only an affirmatively checked claim is ok. Unchecked is not ok."""
        return self.status == HOLDS


@dataclass
class VerifyResult:
    ok: bool
    depth: str
    reason: str
    claims: list[ClaimResult] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "depth": self.depth, "reason": self.reason,
            "claims": [
                {"name": c.name, "status": c.status, "detail": c.detail,
                 "notes": list(c.notes)} for c in self.claims
            ],
            "findings": list(self.findings),
        }


# ---- crypto -----------------------------------------------------------------

def _have_crypto() -> bool:
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401
    except Exception:
        return False
    return True


def verify_ed25519(pubkey_hex: str, sig_hex: str, message: bytes) -> bool:
    """True iff ``sig_hex`` is a valid Ed25519 signature over ``message``."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception:  # pragma: no cover -- guarded by _have_crypto
        return False
    try:
        raw = bytes.fromhex(pubkey_hex)
        if len(raw) != 32:
            return False
        ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(
            bytes.fromhex(sig_hex), message)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def canonical_bundle_bytes(bundle: dict) -> bytes:
    """The exact bytes the issuer signed: every field but ``signature``."""
    return json.dumps(
        {k: v for k, v in bundle.items() if k != "signature"},
        sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")


# ---- audit-chain re-derivation ----------------------------------------------
#
# These two rules must match maverick.audit.signing byte for byte or an honest
# chain reads as tampered. `test_attestation.py` pins them by running this
# verifier and signing.verify_chain over the same fixtures -- clean and every
# tamper variant -- and asserting the two agree, so a drift in either shows up
# as a test failure rather than as a false accusation against a customer.

def audit_row_hash(row: dict) -> str:
    """Recompute a signed audit row's content hash."""
    payload = {k: v for k, v in row.items() if k not in ("hash", "sig")}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8"),
    ).hexdigest()


@dataclass
class ChainWalk:
    breaks: list[str] = field(default_factory=list)
    tip: str = ""
    rows: int = 0
    tools: list[str] = field(default_factory=list)
    unsigned_rows: int = 0
    #: Chain tip after each non-empty row, so a commitment to the first N rows
    #: of a still-growing day-file can be checked as a prefix.
    tips: list[str] = field(default_factory=list)


def walk_chain(text: str, trusted_key_hex: str) -> ChainWalk:
    """Re-verify one day-file's NDJSON: hash links, then signatures.

    ``trusted_key_hex`` is the anchor, not the row's self-declared key. A row
    naming some other ``key_id`` is a break, because a chain is only evidence
    under a key the verifier already trusts.
    """
    walk = ChainWalk()
    prev = ""
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        walk.rows += 1
        # Record the tip after every counted row, including rows we could not
        # parse, so ``tips[k-1]`` always describes the state after k rows and a
        # prefix check lines up with ``_file_tip_and_count``'s row numbering.
        walk.tips.append(prev)
        try:
            row = json.loads(line)
        except ValueError as e:
            walk.breaks.append(f"row {n}: malformed JSON ({e})")
            continue
        if not isinstance(row, dict):
            walk.breaks.append(f"row {n}: not a JSON object")
            continue
        row_hash = row.get("hash")
        sig = row.get("sig")
        key_id = row.get("key_id")
        if not row_hash and not sig and not key_id:
            # Signing was never switched on for this row. Reported separately
            # from tampering: "this deployment did not sign its audit trail" is
            # a true and useful finding, and calling it tampering would be a
            # false accusation.
            walk.unsigned_rows += 1
            continue
        if not (isinstance(row_hash, str) and isinstance(sig, str)
                and isinstance(key_id, str)):
            walk.breaks.append(f"row {n}: hash/sig/key_id missing or not strings")
            continue
        row_prev = row.get("prev_hash", "")
        if not isinstance(row_prev, str) or row_prev != prev:
            walk.breaks.append(
                f"row {n}: prev_hash {str(row_prev)[:12]}... does not link to "
                f"{prev[:12] or '(start of file)'}")
        if audit_row_hash(row) != row_hash:
            walk.breaks.append(f"row {n}: content does not match its recorded hash")
        elif not _is_hex(row_hash):
            # Unreachable while the hash matched a recomputed sha256, but a
            # tampered pair could agree and still not be hex. Flag it rather
            # than let bytes.fromhex raise and abandon every later row -- a
            # tamper-evidence tool that stops looking at the first oddity is
            # the most useful thing an attacker could hope for.
            walk.breaks.append(f"row {n}: hash is not hexadecimal")
        elif not verify_ed25519(trusted_key_hex, sig, bytes.fromhex(row_hash)):
            walk.breaks.append(f"row {n}: signature does not verify under the trusted key")
        if row.get("kind") == "tool_call":
            name = row.get("name")
            if isinstance(name, str) and name:
                walk.tools.append(name)
        prev = row_hash
        walk.tips[-1] = prev
    walk.tip = prev
    return walk


def _is_hex(value: str) -> bool:
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


# ---- claim checks -----------------------------------------------------------

def _as_dict(value: object) -> dict:
    """A mapping or an empty one. Never raises.

    ``bundle["claims"]`` arriving as a list would make a bare ``.get`` chain
    raise ``AttributeError`` and abort the run with a traceback. An auditor
    needs a verdict, not a crash, and "this bundle is malformed" is a verdict.
    """
    return value if isinstance(value, dict) else {}


def _claims_of(bundle: dict, name: str) -> dict:
    return _as_dict(_as_dict(bundle.get("claims")).get(name))


def _risk_rank(level: object) -> int:
    try:
        return _RISK_ORDER.index(str(level).strip().lower())
    except ValueError:
        return -1


def _check_envelope(bundle: dict, observed: list[str] | None) -> ClaimResult:
    """Did every recorded dispatch attempt stay inside the policy envelope?"""
    env = _as_dict(bundle.get("envelope"))
    if not env:
        return ClaimResult("policy_envelope", INDETERMINATE,
                           "the bundle declares no policy envelope")
    if env.get("policy_source") == "unavailable":
        # The issuer could not read its policy: an empty envelope then records
        # a load failure, not an open policy.
        error = str(env.get("policy_error") or "no detail recorded")[:200]
        return ClaimResult("policy_envelope", INDETERMINATE,
                           f"the issuer could not load its policy ({error})")
    notes: list[str] = []
    deny = {str(a) for a in env.get("deny_actions") or []}
    floor = env.get("deny_min_risk")
    risks = env.get("tool_risk") if isinstance(env.get("tool_risk"), dict) else {}
    if not deny and _risk_rank(floor) < 0:
        # Lightwork's community default is an open policy. "No action violated
        # the envelope" is then trivially true and means nothing, so it is
        # reported as inapplicable rather than as a pass. A green badge here
        # would be the single most misleading thing this tool could print.
        return ClaimResult(
            "policy_envelope", NOT_APPLICABLE,
            "the declared envelope forbids nothing, so it constrains nothing")

    claimed = _claims_of(bundle, "policy_envelope")
    calls = observed if observed is not None else claimed.get("tool_calls")
    if not isinstance(calls, list):
        return ClaimResult("policy_envelope", INDETERMINATE,
                           "no record of which actions reached dispatch")
    if observed is None:
        notes.append("action list as recorded by the issuer, not re-derived "
                     "(re-run with --evidence to check it against the chain)")
    if not calls:
        return ClaimResult("policy_envelope", NOT_APPLICABLE,
                           "no dispatch attempts were recorded in the attested window")

    violations: list[str] = []
    for name in {str(c) for c in calls}:
        if name in deny:
            violations.append(f"{name} reached dispatch but is in deny_actions")
        elif _risk_rank(floor) >= 0:
            rank = _risk_rank(risks.get(name))
            if rank < 0:
                notes.append(f"{name}: no declared risk classification, "
                             "cannot check it against deny_min_risk")
            elif rank >= _risk_rank(floor):
                violations.append(
                    f"{name} reached dispatch at declared risk {risks.get(name)!r}, "
                    f"at or above the deny floor {floor!r}")
    if risks:
        notes.append("risk levels are the issuer's declared classification, "
                     "signed but not independently derived")
    # The envelope also carries human-approval and dollar-threshold rules. This
    # claim checks only the DENY rules; proving a human actually approved an
    # action means joining tool-call rows to approval rows, which this schema
    # does not commit to. Say so, because an unchecked rule sitting in a signed
    # envelope otherwise reads as a rule that was checked.
    unchecked = [
        label for label, value in (
            ("require_human_actions", env.get("require_human_actions")),
            ("require_human_min_risk", env.get("require_human_min_risk")),
            ("deny_above", env.get("deny_above")),
            ("require_human_above", env.get("require_human_above")),
        ) if value
    ]
    if unchecked:
        notes.append(
            f"the envelope also declares {', '.join(unchecked)}; this claim "
            "covers only the deny rules and does not check those")
    if violations:
        return ClaimResult("policy_envelope", FAILS,
                           f"{len(violations)} dispatch attempt(s) outside the envelope",
                           sorted(violations) + notes)
    return ClaimResult(
        "policy_envelope", HOLDS,
        f"{len(set(map(str, calls)))} distinct dispatch attempt(s) recorded, "
        "none forbidden",
        notes)


def _check_self_improvement(bundle: dict, receipts: list | None) -> ClaimResult:
    """Did self-improvement ever widen its own authority?

    The bundle's distinctive claim, and the one most easily faked, so it is
    graded strictly. A promotion whose receipt does not say how authority was judged
    proves nothing about authority -- including a receipt written before the
    grading existed. Silence is ``INDETERMINATE``.
    """
    claimed = _claims_of(bundle, "bounded_self_improvement")
    recs = receipts if receipts is not None else claimed.get("promotions")
    if not isinstance(recs, list):
        return ClaimResult("bounded_self_improvement", INDETERMINATE,
                           "the bundle carries no promotion receipts")
    notes: list[str] = []
    if receipts is None:
        notes.append("receipts as recorded by the issuer, not re-read from the "
                     "ledger (re-run with --evidence to check them)")
    if not recs:
        return ClaimResult(
            "bounded_self_improvement", NOT_APPLICABLE,
            "no self-change was promoted in the attested window")

    bad: list[str] = []
    silent: list[str] = []
    probed = declared = 0
    for rec in recs:
        if not isinstance(rec, dict):
            bad.append("a receipt is not an object")
            continue
        rid = str(rec.get("id", "?"))
        grading = rec.get("capability_evidence")
        if grading is None:
            silent.append(f"{rid}: receipt records no capability grading")
        elif grading not in _KNOWN_GRADINGS:
            bad.append(f"{rid}: unrecognised capability grading {grading!r}")
        elif grading == _UNPROVEN:
            silent.append(f"{rid}: capability non-escalation was never proven")
        elif grading == _PROBED_BOUNDED:
            probed += 1
            n = rec.get("capability_probe_tools")
            if not isinstance(n, int) or isinstance(n, bool) or n <= 0:
                bad.append(f"{rid}: claims a capability probe but records no probe size")
        else:
            declared += 1
    if bad:
        return ClaimResult("bounded_self_improvement", FAILS,
                           f"{len(bad)} receipt(s) carry unusable capability evidence",
                           sorted(bad) + notes)
    if silent:
        return ClaimResult(
            "bounded_self_improvement", INDETERMINATE,
            f"{len(silent)} of {len(recs)} promotion(s) cannot show authority "
            "stayed bounded", sorted(silent) + notes)
    if declared:
        notes.append(f"{declared} of {len(recs)} promotion(s) rest on a declared "
                     "verdict rather than a walked capability probe")
    return ClaimResult(
        "bounded_self_improvement", HOLDS,
        f"all {len(recs)} promotion(s) bounded ({probed} probed, {declared} declared)",
        notes)


_DAY_VERIFIED = "verified"
_DAY_UNPROVABLE = "unprovable"
_DAY_FAILED = "failed"


def _check_prefix(entry: dict, walk: ChainWalk, day: str) -> tuple[list[str], list[str]]:
    """Check an open day's commitment: the attested rows are still its opening rows.

    An open day was being appended to at issuance, so growth is expected. What
    must not have changed is the prefix that was attested -- the first ``rows``
    rows, producing the committed tip at that point.
    """
    rows = entry.get("rows")
    tip = str(entry.get("tip") or "")
    if not isinstance(rows, int) or walk.rows < rows:
        return [f"{day}: {walk.rows} rows on disk is fewer than the "
                f"{rows} committed (the log was truncated)"], []
    at_prefix = walk.tips[rows - 1] if 0 < rows <= len(walk.tips) else ""
    if at_prefix != tip:
        return [f"{day}: the first {rows} row(s) no longer produce the committed "
                "tip (attested rows were edited)"], []
    if walk.rows > rows:
        return [], [f"{day}: {walk.rows - rows} row(s) appended after issuance; "
                    "the attested prefix is intact"]
    return [], []


def _check_closed(entry: dict, walk: ChainWalk, day: str) -> list[str]:
    """Check a closed day's commitment: the whole file, exactly as attested."""
    if walk.tip != str(entry.get("tip") or ""):
        return [f"{day}: chain tip does not match the committed tip"]
    if walk.rows != entry.get("rows"):
        return [f"{day}: {walk.rows} rows on disk != {entry.get('rows')} committed"]
    return []


def _check_day(entry: dict, evidence_root: Path,
               key: str) -> tuple[str, list[str], list[str]]:
    """Verify one committed day-file. Returns (outcome, problems, notes)."""
    day = str(entry.get("day", "?"))
    path = evidence_root / f"{day}.ndjson"
    if not path.exists():
        return _DAY_FAILED, [
            f"{day}: committed day-file is missing from the evidence"], []
    try:
        raw = path.read_bytes()
    except OSError as e:  # pragma: no cover -- unreadable evidence file
        return _DAY_FAILED, [f"{day}: cannot read the evidence file ({e})"], []

    # A digest that has moved on is expected for an open day (its commitment is a
    # prefix) and disqualifying for a closed one.
    is_open = bool(entry.get("open"))
    if hashlib.sha256(raw).hexdigest() != str(entry.get("sha256")) and not is_open:
        return _DAY_FAILED, [
            f"{day}: file bytes do not match the committed digest"], []
    if entry.get("sealed"):
        # Encrypted at rest. The digest still proves the file is the exact one
        # attested, which is worth having, but the chain inside it cannot be
        # walked without the tenant's key -- and handing an auditor that key to
        # prove a point would defeat sealing it.
        return _DAY_UNPROVABLE, [], []
    if entry.get("tip") is None or entry.get("rows") is None:
        # Bytes committed, chain unreadable at issue time: there is nothing for a
        # re-walk to compare against, so this is unproven rather than broken.
        return _DAY_UNPROVABLE, [], [
            f"{day}: committed without a chain tip, so a re-walk has nothing to "
            "check against"]

    walk = walk_chain(raw.decode("utf-8", errors="replace"), key)
    if walk.breaks:
        return _DAY_FAILED, [f"{day}: {b}" for b in walk.breaks[:8]], []
    if walk.unsigned_rows:
        return _DAY_FAILED, [
            f"{day}: {walk.unsigned_rows} row(s) are unsigned (audit signing was "
            "off), so they carry no integrity guarantee"], []
    if is_open and entry.get("rows") == 0:
        # An open day committed with no rows attests to nothing beyond the
        # file's existence: there is no prefix to check, so counting it as
        # re-verified would inflate the tally with a day nobody vouched for.
        return _DAY_UNPROVABLE, [], [
            f"{day}: committed with no rows, so nothing about it is attested"]
    if is_open:
        problems, notes = _check_prefix(entry, walk, day)
    else:
        problems, notes = _check_closed(entry, walk, day), []
    if problems:
        return _DAY_FAILED, problems, notes
    return _DAY_VERIFIED, [], notes


def _check_history(bundle: dict, evidence_root: Path | None,
                   key: str) -> ClaimResult:
    """Is the decision history authentic and complete?

    ``key`` is the trusted anchor, never the key embedded in the bundle. A
    bundle carrying a signature but no ``pubkey`` field would otherwise leave
    this walking chains with an empty key and reporting every row as
    unverifiable -- a false accusation against an honest customer.
    """
    commits = _as_dict(bundle.get("commitments"))
    if not commits:
        return ClaimResult("authentic_history", INDETERMINATE,
                           "the bundle commits to no audit evidence")
    days = commits.get("audit_days")
    if not isinstance(days, list) or not days:
        return ClaimResult("authentic_history", NOT_APPLICABLE,
                           "the bundle commits to no audit day-files")
    if evidence_root is None:
        return ClaimResult(
            "authentic_history", INDETERMINATE,
            f"{len(days)} day-file(s) committed; re-run with --evidence "
            "<audit-dir> to check the files against those commitments")

    notes: list[str] = []
    problems: list[str] = []
    sealed_days: list[str] = []
    verified = 0
    committed_days: set[str] = set()

    for entry in days:
        if not isinstance(entry, dict):
            problems.append("a day commitment is not an object")
            continue
        day = str(entry.get("day", "?"))
        committed_days.add(day)
        outcome, day_problems, day_notes = _check_day(entry, evidence_root, key)
        problems.extend(day_problems)
        notes.extend(day_notes)
        if outcome == _DAY_VERIFIED:
            verified += 1
        elif outcome == _DAY_UNPROVABLE:
            sealed_days.append(day)

    # A day-file on disk that the bundle never committed to, from a day already
    # CLOSED at issuance, is a gap in coverage: the bundle attests to a window it
    # did not actually cover. The issuance day itself is excluded -- its file may
    # not have existed when the scan ran and legitimately appears afterwards (the
    # export's own audit row creates it), so flagging it would reject every
    # honest bundle. Days after issuance are ordinary later activity.
    issued_day = str(bundle.get("issued_day") or "")
    try:
        for path in sorted(evidence_root.glob("*.ndjson")):
            day = path.stem
            if len(day) != 10 or day in committed_days:
                continue
            if issued_day and day < issued_day:
                problems.append(
                    f"{day}: day-file predates issuance but the bundle does not "
                    "commit to it (attested window is incomplete)")
    except OSError as e:  # pragma: no cover -- unreadable evidence dir
        problems.append(f"cannot list the evidence directory: {e}")

    if problems:
        return ClaimResult("authentic_history", FAILS,
                           f"{len(problems)} problem(s) in the attested history",
                           sorted(problems)[:20] + notes)
    if sealed_days:
        notes.append("sealed day-files are byte-identical to what was attested, "
                     "but their chains cannot be re-walked without the "
                     "tenant's at-rest key")
        return ClaimResult(
            "authentic_history", INDETERMINATE,
            f"{verified} day-file(s) re-verified, {len(sealed_days)} sealed and "
            "not independently walkable", notes + [f"sealed: {d}" for d in sealed_days])
    return ClaimResult(
        "authentic_history", HOLDS,
        f"{verified} day-file(s) re-verified: hashes link, signatures verify "
        "under the trusted key, and the files match what the bundle committed to",
        notes)


# ---- top level --------------------------------------------------------------

def verify(bundle: dict, *, trusted_key_hex: str,
           evidence_root: Path | str | None = None) -> VerifyResult:
    """Check a bundle against an out-of-band key, optionally corroborating it.

    ``ok`` is True only when the signature verifies against ``trusted_key_hex``
    AND no claim FAILS. A bundle whose every claim is INDETERMINATE is
    ``ok=True`` with depth reported: it is authentic and it proved nothing, and
    conflating that with a clean bill of health is the failure mode this whole
    module is built to avoid. Read the claim table, not just the exit code.
    """
    if not isinstance(bundle, dict):
        return VerifyResult(False, DEPTH_NONE, "bundle is not a JSON object")
    if bundle.get("kind") != BUNDLE_KIND:
        return VerifyResult(False, DEPTH_NONE,
                            f"not a {BUNDLE_KIND} bundle (kind={bundle.get('kind')!r})")
    version = bundle.get("schema_version")
    if version != SCHEMA_VERSION:
        # Refuse rather than guess. A newer bundle may carry claims this
        # verifier does not know how to check, and silently ignoring them would
        # under-report exactly the fields somebody bothered to add.
        return VerifyResult(
            False, DEPTH_NONE,
            f"bundle schema version {version!r} is not {SCHEMA_VERSION} "
            "(use the verifier shipped with the bundle)")
    if not _have_crypto():
        return VerifyResult(False, DEPTH_NONE,
                            "the 'cryptography' package is required to verify")

    sig = bundle.get("signature")
    if not isinstance(sig, dict) or not sig.get("sig"):
        return VerifyResult(False, DEPTH_NONE, "bundle is unsigned")
    anchor = (trusted_key_hex or "").strip().lower()
    if not anchor:
        return VerifyResult(
            False, DEPTH_NONE,
            "a trusted public key is required: a key read out of the bundle "
            "proves only that somebody signed it, not who")
    embedded = str(sig.get("pubkey") or "").strip().lower()
    if embedded and embedded != anchor:
        return VerifyResult(
            False, DEPTH_NONE,
            "the bundle's signing key is not the trusted key (provenance fail)")
    if not verify_ed25519(anchor, str(sig.get("sig")), canonical_bundle_bytes(bundle)):
        return VerifyResult(False, DEPTH_NONE,
                            "signature does not verify over the bundle contents")

    root = Path(evidence_root) if evidence_root else None
    depth = DEPTH_CORROBORATED if root is not None else DEPTH_SIGNED
    findings: list[str] = []
    if root is not None and not root.is_dir():
        findings.append(f"evidence root {root} is not a directory; "
                        "claims fall back to the issuer's own record")
        root = None
        depth = DEPTH_SIGNED

    observed: list[str] | None = None
    receipts: list | None = None
    if root is not None:
        observed, receipts, extra = _reread_evidence(bundle, root, anchor)
        findings.extend(extra)

    claims = [
        _check_envelope(bundle, observed),
        _check_self_improvement(bundle, receipts),
        _check_history(bundle, root, anchor),
    ]
    failed = [c.name for c in claims if c.status == FAILS]
    if failed:
        return VerifyResult(False, depth,
                            f"claim(s) FAILED: {', '.join(failed)}", claims, findings)
    held = sum(1 for c in claims if c.status == HOLDS)
    return VerifyResult(
        True, depth,
        f"signature verified against the trusted key; {held} of {len(claims)} "
        "claim(s) affirmatively hold", claims, findings)


def _reread_evidence(bundle: dict, root: Path,
                     anchor: str) -> tuple[list[str] | None, list | None, list[str]]:
    """Re-derive the action list and promotion receipts from the raw evidence."""
    findings: list[str] = []
    observed: list[str] | None = None
    receipts: list | None = None

    days = _as_dict(bundle.get("commitments")).get("audit_days") or []
    if isinstance(days, list) and days:
        tools: list[str] = []
        readable = skipped = 0
        for entry in days:
            if not isinstance(entry, dict):
                continue
            if entry.get("sealed"):
                skipped += 1
                continue
            path = root / f"{entry.get('day')}.ndjson"
            if not path.exists():
                skipped += 1
                continue
            try:
                tools.extend(walk_chain(
                    path.read_bytes().decode("utf-8", errors="replace"), anchor).tools)
            except OSError as e:
                findings.append(f"cannot read {path.name}: {e}")
                skipped += 1
                continue
            readable += 1
        if readable:
            # Union with what the issuer disclosed, never replace it. Sealed or
            # missing days cannot be walked, so a re-derived list alone can be
            # SHORTER than the signed one -- and then corroborating a bundle
            # would quietly drop a violation the issuer had actually admitted
            # to, making the deeper check the weaker one. The issuer is on the
            # hook for what it signed; re-derivation exists to catch what it
            # left out, so the two are combined.
            declared = _claims_of(bundle, "policy_envelope").get("tool_calls")
            if isinstance(declared, list):
                tools.extend(str(d) for d in declared)
            observed = tools
            if skipped:
                findings.append(
                    f"{skipped} committed day-file(s) could not be re-walked "
                    "(sealed or absent); the action list falls back to the "
                    "issuer's own record for those days")

    ledger = _as_dict(bundle.get("commitments")).get("ledger")
    if isinstance(ledger, dict) and ledger.get("path_name"):
        # The ledger sits in the data directory, the parent of the documented
        # ``--evidence ~/.maverick/audit``; accept it in either place.
        name = str(ledger["path_name"])
        path = root / name if (root / name).exists() else root.parent / name
        if path.exists():
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != str(ledger.get("sha256")):
                findings.append(
                    "the promotion ledger on disk does not match the committed "
                    "digest; its receipts are not the attested ones")
            else:
                try:
                    loaded = json.loads(raw.decode("utf-8"))
                except ValueError as e:
                    findings.append(f"promotion ledger is unreadable: {e}")
                else:
                    if isinstance(loaded, list):
                        receipts = loaded
                    elif isinstance(loaded, dict) and isinstance(
                            loaded.get("records"), list):
                        receipts = loaded["records"]
                    else:
                        findings.append("promotion ledger has an unexpected shape")
    return observed, receipts, findings


_STATUS_MARK = {HOLDS: "HOLDS", FAILS: "FAILS", INDETERMINATE: "INDET",
                NOT_APPLICABLE: "N/A  "}


def format_report(result: VerifyResult) -> str:
    """The human-readable verdict."""
    width = 74
    lines = ["=" * width,
             "  LIGHTWORK ATTESTATION -- INDEPENDENT VERIFICATION",
             "=" * width]
    verdict = "VERIFIED" if result.ok else "REJECTED"
    lines.append(f"  result: {verdict}   (depth: {result.depth})")
    lines.append(f"  {result.reason}")
    if result.claims:
        lines.append("-" * width)
        for c in result.claims:
            lines.append(f"  [{_STATUS_MARK.get(c.status, c.status)}]  "
                         f"{c.name:26}  {c.detail}")
            for note in c.notes:
                lines.append(f"           - {note}")
    if result.findings:
        lines.append("-" * width)
        for f in result.findings:
            lines.append(f"  ! {f}")
    lines.append("=" * width)
    if result.ok and not any(c.status == HOLDS for c in result.claims):
        lines.append("  NOTE: the bundle is authentic but establishes no claim.")
        lines.append("=" * width)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="attestation_verify",
        description="Independently verify a Lightwork attestation bundle.")
    ap.add_argument("bundle", help="path to the attestation bundle JSON")
    ap.add_argument("--key", required=True, metavar="HEX",
                    help="the publisher's Ed25519 public key, obtained OUT OF "
                         "BAND (not from the bundle)")
    ap.add_argument("--evidence", metavar="DIR", default=None,
                    help="audit directory, to check the bundle's commitments "
                         "against the underlying files")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    try:
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"cannot read bundle: {e}", file=sys.stderr)
        return 2
    result = verify(bundle, trusted_key_hex=args.key, evidence_root=args.evidence)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_report(result))
    return 0 if result.ok else 1


__all__ = [
    "BUNDLE_KIND", "DEPTH_CORROBORATED", "DEPTH_NONE", "DEPTH_SIGNED", "FAILS",
    "HOLDS", "INDETERMINATE", "NOT_APPLICABLE", "SCHEMA_VERSION", "ChainWalk",
    "ClaimResult", "VerifyResult", "audit_row_hash", "canonical_bundle_bytes",
    "format_report", "main", "verify", "verify_ed25519", "walk_chain",
]


if __name__ == "__main__":  # pragma: no cover -- standalone entry point
    sys.exit(main())
