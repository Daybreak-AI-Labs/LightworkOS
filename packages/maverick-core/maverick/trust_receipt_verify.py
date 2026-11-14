"""Third-party verifier for a Lightwork trust receipt.

**This module imports nothing from maverick.** Standard library plus
``cryptography``, deliberately: a receipt is handed to someone who trusts
neither the operator nor the vendor -- an auditor, a regulator, a customer's
customer -- and they must be able to check it without installing our platform
or asking anyone's permission. ``maverick attest receipt export-verifier``
copies this exact file, and it runs on its own::

    python trust_receipt_verify.py receipt.json --key <publisher-pubkey-hex>
    python trust_receipt_verify.py receipt.json --key <hex> --anchor-digest <sha256>

A receipt is evidence about ONE audited decision: "tool X was denied under
rule R for principal P at time T", "tool X was attempted", or (from an ok
result row) "tool X executed". It carries the signed audit row itself and,
only after an explicit disclosure opt-in, the later rows needed to walk a
linear chain to its tip. It may also carry the signed checkpoint committing
that tip. Verification re-derives everything:

* the envelope signature, under a key the verifier obtained OUT OF BAND;
* the row's own hash and signature (the decision really was recorded);
* the claim, recomputed from the row -- the receipt's human-readable claim is
  never trusted, it must equal what the row says;
* for a tool result, an optional full signed call row whose explicit
  call-commitment matches the result; this is a separate disclosure opt-in;
* the hash links from the row to the committed tip (the row really sits in
  that chain at that position);
* the checkpoint record's signature and its agreement with the tip.

Three depths are reported and they are not synonyms. ``signed`` means the
issuer signed a genuine row. ``chained`` means the row provably links to a tip
the issuer committed to. ``anchored`` means that commitment matched a digest
the verifier retained OUTSIDE the receipt (``--anchor-digest``) -- the only
depth at which the issuer could not have quietly re-written history after the
fact. Re-reading a file from the issuer's mutable checkpoint directory validates
byte agreement but is not independent anchoring evidence. An issuer-signed
commitment with nothing independently retained to compare it to is still just
the issuer's word, and this tool says so.

Two honest limits. A receipt is point in time: a later GDPR erasure lawfully
rewrites and re-signs the day-file, so an old receipt stays self-consistent
but no longer matches the live log. And a key kept on the same host as the
log proves integrity against accidental edits, not tamper-evidence against an
actor who can read that key; the receipt's ``issuer.key_custody`` field is
surfaced so the reader can weigh it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

LEGACY_SCHEMA_VERSION = 1
SCHEMA_VERSION = 2
RECEIPT_KIND = "maverick-trust-receipt"
CHECKPOINT_SCHEMA = "lightwork.audit.checkpoint.v2"
TOOL_CALL_COMMITMENT_ALGORITHM = "sha256:lightwork.tool-call-id:v2"

HOLDS = "HOLDS"
FAILS = "FAILS"
INDETERMINATE = "INDETERMINATE"
NOT_APPLICABLE = "NOT_APPLICABLE"

#: Depth reached by a verification run, weakest first.
DEPTH_NONE = "unverified"
DEPTH_SIGNED = "signed"
DEPTH_CHAINED = "chained"
DEPTH_ANCHORED = "anchored"

_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SIG_RE = re.compile(r"^[0-9a-f]{128}$")
_CALL_ID_RE = re.compile(r"^[0-9a-f]{24}$")
_CHECKPOINT_FILE_RE = re.compile(r"^audit-checkpoint-\d{20}\.ndjson$")
_MAX_CHECKPOINT_BYTES = 64 * 1024
_MAX_RECEIPT_BYTES = 8 * 1024 * 1024
_MAX_SUFFIX_ROWS = 10_000
_MAX_SUFFIX_ROW_BYTES = 256 * 1024
_MAX_EXECUTION_PAIR_ROW_BYTES = 256 * 1024
_MAX_JSON_DEPTH = 64
_MAX_JSON_ITEMS = 100_000

# Audit kinds that record a decision NOT to act. Kept in step with
# maverick.audit.events by test_trust_receipt.py.
_DENIED_KINDS = frozenset({
    "governance_denied", "capability_denied", "sandbox_denied", "shield_block",
    "egress_blocked", "agent_trust_denied",
})
_NOT_GRANTED = "human approval not granted"

#: Row fields a claim is derived from. Obligation tags are optional and only
#: present on rows written by a deployment with compiled obligations.
_CLAIM_ROW_FIELDS = (
    "principal", "agent", "goal_id", "call_id", "rule", "reason",
    "disposition", "obligation_id", "regulation", "article",
)
_LEGACY_CLAIM_ROW_FIELDS = (
    "principal", "agent", "goal_id", "rule", "reason",
    "obligation_id", "regulation", "article",
)


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


def audit_row_hash(row: dict) -> str:
    """Recompute a signed audit row's content hash.

    Must match ``maverick.audit.signing`` byte for byte: default separators,
    sorted keys, ``ensure_ascii``. ``test_trust_receipt.py`` pins the two
    against the production signer so a drift in either fails a test instead
    of reading an honest row as forged.
    """
    payload = {k: v for k, v in row.items() if k not in ("hash", "sig")}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8"),
    ).hexdigest()


def key_id_of(pubkey_hex: str) -> str:
    """The 16-hex-char key id the signer stamps on every row."""
    return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:16]


def tool_call_commitment(*, call_id: str) -> str:
    """Mirror the production v2 commitment without importing Lightwork.

    Persisted identity fields are compared separately below because the writer
    can validly resolve or pseudonymize them before signing.
    """
    if not isinstance(call_id, str) or not _CALL_ID_RE.fullmatch(call_id):
        raise ValueError("tool call_id must be exactly 24 lowercase hex characters")
    payload = {"domain": "lightwork.tool-call-id.v2", "call_id": call_id}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _legacy_tool_call_commitment(*, call_id: str, name: str, agent: str,
                                 goal_id: int | None, origin: str,
                                 principal: str | None) -> str:
    """Verify pre-v2 rows that did not carry an explicit algorithm field."""
    if not isinstance(call_id, str) or not _CALL_ID_RE.fullmatch(call_id):
        raise ValueError("tool call_id must be exactly 24 lowercase hex characters")
    if not isinstance(name, str) or not name:
        raise ValueError("tool name must be a non-empty string")
    if not isinstance(agent, str) or not agent:
        raise ValueError("tool agent must be a non-empty string")
    if not isinstance(origin, str) or not origin:
        raise ValueError("tool origin must be a non-empty string")
    if principal is not None and not isinstance(principal, str):
        raise ValueError("tool principal must be a string or null")
    if goal_id is not None and (
        not isinstance(goal_id, int) or isinstance(goal_id, bool)
    ):
        raise ValueError("tool goal_id must be an integer or null")
    payload = {
        "domain": "lightwork.tool-call.v1",
        "call_id": call_id,
        "name": name,
        "agent": agent,
        "goal_id": goal_id,
        "origin": origin,
        "principal": principal,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


# ---- claim derivation --------------------------------------------------------

def _execution_pair_fields_match(row: dict, execution_pair: object) -> bool:
    pair = execution_pair if isinstance(execution_pair, dict) else {}
    call = pair.get("call_row") if isinstance(pair.get("call_row"), dict) else {}
    call_id = row.get("call_id")
    call_commitment = call.get("call_commitment")
    result_commitment = row.get("call_commitment")
    algorithm = call.get("call_commitment_algorithm")
    if not (
        isinstance(call_commitment, str)
        and _HASH_RE.fullmatch(call_commitment)
        and result_commitment == call_commitment
        and row.get("call_commitment_algorithm") == algorithm
    ):
        return False
    try:
        if algorithm == TOOL_CALL_COMMITMENT_ALGORITHM:
            expected_commitment = tool_call_commitment(
                call_id=call.get("call_id"),
            )
        elif algorithm is None:
            expected_commitment = _legacy_tool_call_commitment(
                call_id=call.get("call_id"),
                name=call.get("name"),
                agent=call.get("agent"),
                goal_id=call.get("goal_id"),
                origin=call.get("origin"),
                principal=call.get("principal"),
            )
        else:
            return False
    except (TypeError, ValueError):
        return False
    return bool(
        row.get("kind") == "tool_result"
        and isinstance(call_id, str)
        and _CALL_ID_RE.fullmatch(call_id)
        and call.get("kind") == "tool_call"
        and call.get("call_id") == call_id
        and isinstance(call.get("name"), str)
        and bool(call.get("name"))
        and call.get("name") == row.get("name")
        and isinstance(call.get("agent"), str)
        and bool(call.get("agent"))
        and call.get("agent") == row.get("agent")
        and (
            call.get("goal_id") is None
            or (
                isinstance(call.get("goal_id"), int)
                and not isinstance(call.get("goal_id"), bool)
            )
            or isinstance(call.get("goal_id"), str)
        )
        and call.get("goal_id") == row.get("goal_id")
        and isinstance(call.get("origin"), str)
        and bool(call.get("origin"))
        and call.get("origin") == row.get("origin")
        and (
            call.get("principal") is None
            or isinstance(call.get("principal"), str)
        )
        and call.get("principal") == row.get("principal")
        and call_commitment == expected_commitment
    )


def derive_claim(row: dict, execution_pair: object = None) -> dict:
    """What this row says happened, computed from the row alone.

    The minter uses this same function, so a receipt whose stated claim differs
    from the derived one has been edited after minting -- or was minted by
    something that is not this code. Either way it FAILS.
    """
    kind = row.get("kind")
    if kind == "governance_denied" and row.get("reason") == _NOT_GRANTED:
        decision = "require_human_not_granted"
    elif kind in _DENIED_KINDS:
        decision = "denied"
    elif kind == "autonomy_gated":
        decision = "gated"
    elif kind == "tool_call":
        # TOOL_CALL is written before dispatch.  It proves that a call reached
        # the governed execution boundary, not that the tool existed or
        # completed.  Only an ok TOOL_RESULT can support "executed".
        decision = "attempted"
    elif kind == "tool_result":
        paired = _execution_pair_fields_match(row, execution_pair)
        # Lost responses and interrupted result collection leave the effect
        # unresolved even when dispatch is paired or transport status is known.
        if row.get("disposition") == "execution_unknown":
            decision = "execution_unknown"
        elif row.get("status") == "ok" and paired:
            decision = "executed"
        elif row.get("status") == "error" and paired:
            decision = "failed"
        elif row.get("status") == "ok":
            decision = "result_recorded_ok_unpaired"
        elif row.get("status") == "error":
            decision = "result_recorded_error_unpaired"
        else:
            decision = "result_recorded_unknown_status"
    elif kind == "consent_result":
        decision = str(row.get("decision") or "")
    elif kind == "approval_decision":
        decision = str(row.get("status") or "")
    else:
        decision = "recorded"
    claim = {
        "kind": kind, "decision": decision,
        "tool": row.get("tool") or row.get("name"),
        "occurred_at": row.get("ts"),
    }
    for name in _CLAIM_ROW_FIELDS:
        if row.get(name) is not None:
            claim[name] = row[name]
    return claim


def _derive_legacy_claim(row: dict) -> dict:
    """Reproduce the immutable schema-v1 claim contract exactly.

    Version 1 predated paired call/result evidence and described a signed
    ``tool_call`` row as ``executed``.  The v2 public derivation above remains
    deliberately stricter; this helper exists only behind the explicit v1
    receipt dispatcher so an upgrade can still authenticate already-issued
    evidence without weakening newly minted receipts.
    """
    kind = row.get("kind")
    if kind == "governance_denied" and row.get("reason") == _NOT_GRANTED:
        decision = "require_human_not_granted"
    elif kind in _DENIED_KINDS:
        decision = "denied"
    elif kind == "autonomy_gated":
        decision = "gated"
    elif kind == "tool_call":
        decision = "executed"
    elif kind == "consent_result":
        decision = str(row.get("decision") or "")
    elif kind == "approval_decision":
        decision = str(row.get("status") or "")
    else:
        decision = "recorded"
    claim = {
        "kind": kind,
        "decision": decision,
        "tool": row.get("tool") or row.get("name"),
        "occurred_at": row.get("ts"),
    }
    for name in _LEGACY_CLAIM_ROW_FIELDS:
        if row.get(name) is not None:
            claim[name] = row[name]
    return claim


# ---- checks ----------------------------------------------------------------

def _as_dict(value: object) -> dict:
    """A mapping or an empty one. Never raises -- a verdict, not a traceback."""
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True)
class _TrustedKey:
    pubkey: str
    not_before: float | None = None
    not_after: float | None = None
    revoked_at: float | None = None


def _finite_time(value: object) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("key validity times must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("key validity times must be finite numeric values") from exc
    if not (-1e20 < parsed < 1e20):
        raise ValueError("key validity times must be finite")
    return parsed


def _normalise_keys(trusted_keys) -> dict[str, list[_TrustedKey]]:
    """Role-specific trusted keys, optionally with validity/revocation windows.

    A plain hexadecimal string remains supported.  A stricter caller may pass
    ``{"pubkey": HEX, "not_before": TS, "not_after": TS,
    "revoked_at": TS}`` records.  The verifier evaluates the signer at the
    record time for historical evidence and the verifier's current time for
    current envelope/checkpoint authorities.
    """
    out: dict[str, list[_TrustedKey]] = {}
    for key in trusted_keys or ():
        if isinstance(key, dict):
            hexkey = str(key.get("pubkey") or key.get("key") or "").strip().lower()
            try:
                policy = _TrustedKey(
                    hexkey,
                    not_before=_finite_time(key.get("not_before")),
                    not_after=_finite_time(key.get("not_after")),
                    revoked_at=_finite_time(key.get("revoked_at")),
                )
            except (TypeError, ValueError, OverflowError):
                continue
            if (
                policy.not_before is not None
                and policy.not_after is not None
                and policy.not_before > policy.not_after
            ):
                continue
        else:
            hexkey = str(key or "").strip().lower()
            policy = _TrustedKey(hexkey)
        try:
            if len(bytes.fromhex(hexkey)) != 32:
                continue
        except ValueError:
            continue
        out.setdefault(key_id_of(hexkey), []).append(policy)
    return out


def _timestamp(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            parsed = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return parsed if -1e20 < parsed < 1e20 else None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return parsed.timestamp()
    return None


def _trusted_at(policies: list[_TrustedKey], when: float | None,
                pubkey: str | None = None) -> _TrustedKey | None:
    if when is None:
        return None
    for policy in policies:
        if pubkey is not None and policy.pubkey != pubkey:
            continue
        if policy.not_before is not None and when < policy.not_before:
            continue
        if policy.not_after is not None and when > policy.not_after:
            continue
        if policy.revoked_at is not None and when >= policy.revoked_at:
            continue
        return policy
    return None


def _path_is_alias(path: Path, info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = int(getattr(info, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    if reparse and attributes & reparse:
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_ino != 0
        and right.st_ino != 0
        and (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    )


def _stable_read_regular_file(path: Path, *, maximum_bytes: int,
                              attempts: int = 3) -> bytes:
    """Bounded, race-aware read that rejects aliases and non-regular files."""
    last_error = "file changed while it was being read"
    for _attempt in range(attempts):
        try:
            before = path.lstat()
        except OSError as exc:
            raise ValueError(f"cannot inspect {path}") from exc
        if _path_is_alias(path, before) or not stat.S_ISREG(before.st_mode):
            raise ValueError(f"refusing non-regular or aliased file: {path}")
        if before.st_nlink != 1:
            raise ValueError(f"refusing multiply-linked file: {path}")
        if before.st_size > maximum_bytes:
            raise ValueError(f"file exceeds {maximum_bytes} bytes: {path}")
        try:
            with open(path, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not _same_identity(before, opened):
                    last_error = f"file identity changed before read: {path}"
                    continue
                raw = stream.read(maximum_bytes + 1)
                after_handle = os.fstat(stream.fileno())
        except OSError as exc:
            last_error = f"cannot read {path}: {exc}"
            continue
        if len(raw) > maximum_bytes:
            raise ValueError(f"file exceeds {maximum_bytes} bytes: {path}")
        try:
            after_path = path.lstat()
        except OSError as exc:
            last_error = f"cannot re-inspect {path}: {exc}"
            continue
        stable = (
            not _path_is_alias(path, after_path)
            and stat.S_ISREG(after_path.st_mode)
            and after_path.st_nlink == 1
            and _same_identity(before, after_handle)
            and _same_identity(after_handle, after_path)
            and before.st_size == after_handle.st_size == after_path.st_size == len(raw)
            and before.st_mtime_ns
            == after_handle.st_mtime_ns
            == after_path.st_mtime_ns
        )
        if stable:
            return raw
        last_error = f"file changed while it was being read: {path}"
    raise ValueError(last_error)


def _json_shape_problem(value: object, *, subject: str,
                        maximum_text_bytes: int) -> str | None:
    """Bound one already-decoded JSON value without recursive traversal."""
    stack: list[tuple[object, int]] = [(value, 0)]
    items = 0
    text_bytes = 0
    while stack:
        item, depth = stack.pop()
        items += 1
        if items > _MAX_JSON_ITEMS:
            return f"{subject} exceeds the maximum JSON item count"
        if depth > _MAX_JSON_DEPTH:
            return f"{subject} exceeds the maximum JSON nesting depth"
        if isinstance(item, dict):
            stack.extend(
                (nested, depth + 1)
                for pair in item.items()
                for nested in pair
            )
        elif isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)
        elif isinstance(item, str):
            try:
                text_bytes += len(item.encode("utf-8"))
            except UnicodeError:
                return f"{subject} contains text that is not valid UTF-8"
            if text_bytes > maximum_text_bytes:
                return f"{subject} exceeds the maximum decoded text size"
    return None


def _receipt_limits_problem(receipt: object) -> str | None:
    """Reject resource-exhaustion shapes before cryptographic traversal."""
    problem = _json_shape_problem(
        receipt,
        subject="receipt",
        maximum_text_bytes=_MAX_RECEIPT_BYTES,
    )
    if problem:
        return problem
    if not isinstance(receipt, dict):
        return None
    chain = receipt.get("chain")
    suffix = chain.get("suffix_ndjson") if isinstance(chain, dict) else None
    if isinstance(suffix, list):
        if len(suffix) > _MAX_SUFFIX_ROWS:
            return f"receipt carries more than {_MAX_SUFFIX_ROWS} suffix rows"
        for row in suffix:
            if not isinstance(row, str):
                return "receipt suffix rows must be JSON strings"
            try:
                row_size = len(row.encode("utf-8"))
            except UnicodeError:
                return "receipt suffix contains text that is not valid UTF-8"
            if row_size > _MAX_SUFFIX_ROW_BYTES:
                return "receipt carries an oversized suffix row"
    pair = receipt.get("execution_pair")
    call = pair.get("call_row") if isinstance(pair, dict) else None
    if call is not None:
        if not isinstance(call, dict):
            return "receipt execution pair call row must be a JSON object"
        try:
            call_size = len(json.dumps(
                call, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8"))
        except (TypeError, ValueError, UnicodeError, RecursionError):
            return "receipt execution pair call row is not bounded valid JSON"
        if call_size > _MAX_EXECUTION_PAIR_ROW_BYTES:
            return "receipt carries an oversized execution pair call row"
    commitment = receipt.get("commitment")
    raw_line = commitment.get("raw_line") if isinstance(commitment, dict) else None
    if isinstance(raw_line, str):
        try:
            raw_line_size = len(raw_line.encode("utf-8"))
        except UnicodeError:
            return "receipt checkpoint line is not valid UTF-8"
        if raw_line_size > _MAX_CHECKPOINT_BYTES:
            return "receipt carries an oversized raw checkpoint line"
    return None


def load_receipt(path: Path | str) -> dict:
    """Read one receipt under the standalone verifier's hard resource limits."""
    raw = _stable_read_regular_file(Path(path), maximum_bytes=_MAX_RECEIPT_BYTES)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError(f"receipt is not bounded valid UTF-8 JSON: {exc}") from exc
    problem = _receipt_limits_problem(parsed)
    if problem:
        raise ValueError(problem)
    if not isinstance(parsed, dict):
        raise ValueError("receipt is not a JSON object")
    return parsed


def _signed_row_problem(row: object, trusted: dict[str, list[_TrustedKey]],
                        label: str, *, authorization_time: float | None = None,
                        authorization_label: str = "record time") -> str | None:
    """Why ``row`` is not a genuine signed audit row, or None if it is."""
    if not isinstance(row, dict):
        return f"{label}: not a JSON object"
    row_hash, sig, key_id = row.get("hash"), row.get("sig"), row.get("key_id")
    if not (isinstance(row_hash, str) and isinstance(sig, str)
            and isinstance(key_id, str)):
        return f"{label}: hash/sig/key_id missing or not strings"
    if not (_HASH_RE.match(row_hash) and _SIG_RE.match(sig) and _KEY_ID_RE.match(key_id)):
        return f"{label}: hash/sig/key_id are not well-formed hex"
    try:
        computed_hash = audit_row_hash(row)
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return f"{label}: content is not bounded canonical JSON"
    if computed_hash != row_hash:
        return f"{label}: content does not match its recorded hash"
    policies = trusted.get(key_id) or []
    if not policies:
        return f"{label}: signed by key {key_id}, which is not a trusted key"
    signed_at = authorization_time
    if signed_at is None:
        signed_at = _timestamp(
            row.get("created_at")
            if label == "commitment record" and row.get("created_at") is not None
            else row.get("ts")
        )
    policy = _trusted_at(policies, signed_at)
    if policy is None:
        return f"{label}: signing key {key_id} was not valid at {authorization_label}"
    if not verify_ed25519(policy.pubkey, sig, bytes.fromhex(row_hash)):
        return f"{label}: signature does not verify under the trusted key"
    return None


def _check_row(receipt: dict, trusted: dict[str, list[_TrustedKey]]) -> ClaimResult:
    """Is the embedded audit row genuine, and is it the row the locator names?"""
    row = _as_dict(receipt.get("row"))
    if not row:
        return ClaimResult("row_integrity", FAILS, "the receipt carries no audit row")
    problem = _signed_row_problem(row, trusted, "row")
    if problem:
        return ClaimResult("row_integrity", FAILS, problem)
    locator = _as_dict(receipt.get("locator"))
    if locator.get("hash") != row.get("hash"):
        return ClaimResult("row_integrity", FAILS,
                           "the locator names a different row than the one embedded")
    return ClaimResult(
        "row_integrity", HOLDS,
        f"row {str(row.get('hash'))[:12]}... hashes to its content and is signed "
        f"by trusted key {row.get('key_id')}")


def _check_claim(receipt: dict) -> ClaimResult:
    """Does the stated claim equal what the row actually records?"""
    stated = _as_dict(receipt.get("claim"))
    derived = derive_claim(
        _as_dict(receipt.get("row")), receipt.get("execution_pair"),
    )
    if stated != derived:
        drifted = sorted(k for k in set(stated) | set(derived)
                         if stated.get(k) != derived.get(k))
        return ClaimResult(
            "claim_consistency", FAILS,
            "the stated claim does not match the row it cites",
            [f"differs in: {', '.join(drifted)}"])
    what = f"{derived.get('decision')} {derived.get('tool') or '(no tool)'}"
    if derived.get("rule"):
        what += f" under rule {derived['rule']}"
    if derived.get("disposition"):
        what += f" with disposition {derived['disposition']}"
    return ClaimResult("claim_consistency", HOLDS, what)


def _check_legacy_claim(receipt: dict) -> ClaimResult:
    """Validate a schema-v1 claim using only the historical v1 derivation."""
    stated = _as_dict(receipt.get("claim"))
    derived = _derive_legacy_claim(_as_dict(receipt.get("row")))
    if stated != derived:
        drifted = sorted(
            key
            for key in set(stated) | set(derived)
            if stated.get(key) != derived.get(key)
        )
        return ClaimResult(
            "claim_consistency",
            FAILS,
            "the stated legacy claim does not match the row it cites",
            [f"differs in: {', '.join(drifted)}"],
        )
    what = f"{derived.get('decision')} {derived.get('tool') or '(no tool)'}"
    if derived.get("rule"):
        what += f" under rule {derived['rule']}"
    return ClaimResult("claim_consistency", HOLDS, what)


def _check_disclosure(receipt: dict) -> ClaimResult:
    """Does the signed disclosure summary match the full rows actually carried?"""
    disclosure = _as_dict(receipt.get("disclosure"))
    chain = _as_dict(receipt.get("chain"))
    suffix = chain.get("suffix_ndjson")
    suffix_count = len(suffix) if isinstance(suffix, list) else 0
    pair = _as_dict(receipt.get("execution_pair"))
    pair_included = bool(pair)
    expected = {
        "cited_row_included": True,
        "suffix_rows_included": suffix_count,
        "execution_pair_included": pair_included,
        "execution_pair_discloses_full_call_row": pair_included,
    }
    if disclosure != expected:
        return ClaimResult(
            "disclosure", FAILS,
            "the signed disclosure summary does not match the receipt contents",
        )
    detail = f"cited row plus {suffix_count} suffix row(s) disclosed"
    if pair_included:
        detail += "; one full signed call row disclosed by explicit opt-in"
    return ClaimResult("disclosure", HOLDS, detail)


def _check_execution_pair(receipt: dict,
                          trusted: dict[str, list[_TrustedKey]]) -> ClaimResult:
    """Does an executed/failed result bind to one earlier genuine call row?"""
    result = _as_dict(receipt.get("row"))
    if result.get("kind") != "tool_result":
        if receipt.get("execution_pair") not in (None, {}):
            return ClaimResult(
                "execution_pair", FAILS,
                "a non-result receipt must not carry an execution pair",
            )
        return ClaimResult(
            "execution_pair", NOT_APPLICABLE,
            "the cited row is not a tool result",
        )
    pair = _as_dict(receipt.get("execution_pair"))
    if not pair:
        return ClaimResult(
            "execution_pair", INDETERMINATE,
            "the result has no matching signed call row; execution is not claimed",
        )
    call = _as_dict(pair.get("call_row"))
    locator = _as_dict(pair.get("locator"))
    problem = _signed_row_problem(call, trusted, "paired call row")
    if problem:
        return ClaimResult("execution_pair", FAILS, problem)
    if not _execution_pair_fields_match(result, pair):
        return ClaimResult(
            "execution_pair", FAILS,
            "the paired call/result correlation fields or call commitment do not match",
        )
    if result.get("status") not in ("ok", "error"):
        return ClaimResult(
            "execution_pair", FAILS,
            "the paired result status is not one of the closed values 'ok' or 'error'",
        )
    result_locator = _as_dict(receipt.get("locator"))
    call_position = locator.get("position")
    result_position = result_locator.get("position")
    if (
        locator.get("day") != result_locator.get("day")
        or locator.get("hash") != call.get("hash")
        or not isinstance(call_position, int)
        or not isinstance(result_position, int)
        or call_position < 1
        or call_position >= result_position
    ):
        return ClaimResult(
            "execution_pair", FAILS,
            "the paired call locator is not an earlier row in the cited audit day",
        )
    call_time, result_time = _timestamp(call.get("ts")), _timestamp(result.get("ts"))
    if call_time is None or result_time is None or call_time > result_time:
        return ClaimResult(
            "execution_pair", FAILS,
            "the paired call/result timestamps are missing or out of order",
        )
    return ClaimResult(
        "execution_pair", HOLDS,
        f"result is paired to signed call {str(call.get('hash'))[:12]}... "
        f"at row {call_position}",
    )


def _check_chain(receipt: dict, trusted: dict[str, list[_TrustedKey]]) -> ClaimResult:
    """Does the row provably link, row by row, to the committed tip?"""
    chain = _as_dict(receipt.get("chain"))
    row = _as_dict(receipt.get("row"))
    locator = _as_dict(receipt.get("locator"))
    if not chain:
        return ClaimResult("chain_linkage", INDETERMINATE,
                           "the receipt carries no chain commitment")
    suffix = chain.get("suffix_ndjson")
    tip, count, position = chain.get("tip_hash"), chain.get("row_count"), locator.get("position")
    if not isinstance(suffix, list) or not isinstance(count, int) or not isinstance(position, int):
        return ClaimResult("chain_linkage", FAILS, "chain commitment is malformed")
    if position + len(suffix) != count:
        if not suffix and position < count:
            return ClaimResult(
                "chain_linkage", INDETERMINATE,
                f"the receipt omits the {count - position} row(s) after the cited "
                "one, so the link to the tip cannot be walked")
        return ClaimResult(
            "chain_linkage", FAILS,
            f"position {position} + {len(suffix)} following row(s) != committed "
            f"row count {count}")
    prev = str(row.get("hash") or "")
    for n, line in enumerate(suffix, start=position + 1):
        try:
            nxt = json.loads(line)
        except (TypeError, ValueError, RecursionError):
            return ClaimResult(
                "chain_linkage", FAILS,
                f"row {n}: malformed or excessively nested JSON",
            )
        limits_problem = _json_shape_problem(
            nxt,
            subject=f"row {n}",
            maximum_text_bytes=_MAX_SUFFIX_ROW_BYTES,
        )
        if limits_problem:
            return ClaimResult("chain_linkage", FAILS, limits_problem)
        problem = _signed_row_problem(nxt, trusted, f"row {n}")
        if problem:
            return ClaimResult("chain_linkage", FAILS, problem)
        if nxt.get("prev_hash") != prev:
            return ClaimResult("chain_linkage", FAILS,
                               f"row {n}: prev_hash does not link to the row before it")
        prev = str(nxt["hash"])
    if prev != tip:
        return ClaimResult("chain_linkage", FAILS,
                           "walking the rows does not arrive at the committed tip")
    return ClaimResult(
        "chain_linkage", HOLDS,
        f"row {position} of {count} links through {len(suffix)} following row(s) "
        f"to tip {str(tip)[:12]}...")


def _checkpoint_problem(commitment: dict, record: dict, chain: dict,
                        locator: dict) -> str | None:
    if record.get("schema") != CHECKPOINT_SCHEMA:
        return f"checkpoint schema is not {CHECKPOINT_SCHEMA}"
    if record.get("record_type") != "checkpoint":
        return f"checkpoint record_type is {record.get('record_type')!r}, not 'checkpoint'"
    if record.get("prev_hash") != "":
        return "a checkpoint record must be a genesis row"
    raw_line = commitment.get("raw_line")
    if not isinstance(raw_line, str):
        return "checkpoint commitment carries no raw record line"
    try:
        parsed = json.loads(raw_line)
        limits_problem = _json_shape_problem(
            parsed,
            subject="raw checkpoint record",
            maximum_text_bytes=_MAX_CHECKPOINT_BYTES,
        )
        if limits_problem:
            return limits_problem
        if parsed != record:
            return "the raw checkpoint line does not parse to the embedded record"
    except (ValueError, RecursionError):
        return "the raw checkpoint line is not bounded valid JSON"
    if hashlib.sha256(raw_line.encode("utf-8")).hexdigest() != commitment.get("raw_sha256"):
        return "raw_sha256 does not match the raw checkpoint line"
    return _agrees_problem(record, chain, locator)


def _agrees_problem(record: dict, chain: dict, locator: dict) -> str | None:
    if record.get("day") != locator.get("day"):
        return "the commitment is for a different day than the cited row"
    if record.get("tip_hash") != chain.get("tip_hash"):
        return "the commitment's tip does not match the receipt's chain tip"
    if record.get("row_count") != chain.get("row_count"):
        return "the commitment's row count does not match the receipt's chain"
    return None


def _check_commitment(receipt: dict,
                      evidence_trusted: dict[str, list[_TrustedKey]],
                      checkpoint_trusted: dict[str, list[_TrustedKey]], *,
                      verification_time: float,
                      anchor_digest: str | None,
                      checkpoint_dir: Path | None) -> tuple[ClaimResult, bool]:
    """Is the tip committed to, and did that commitment match anything external?

    Returns the claim and whether an OUT-OF-BAND corroboration succeeded.
    """
    commitment = _as_dict(receipt.get("commitment"))
    if not commitment:
        return ClaimResult("commitment", INDETERMINATE,
                           "the receipt's tip is not committed to by any anchor"), False
    record = _as_dict(commitment.get("record"))
    source = commitment.get("source")
    chain, locator = _as_dict(receipt.get("chain")), _as_dict(receipt.get("locator"))
    if source == "checkpoint":
        problem = _signed_row_problem(
            record, checkpoint_trusted, "commitment record",
            authorization_time=verification_time,
            authorization_label="verification time",
        )
        if problem is None:
            problem = _checkpoint_problem(commitment, record, chain, locator)
    elif source == "anchor_ledger":
        problem = _signed_row_problem(
            record, evidence_trusted, "commitment record",
        )
        if problem is None:
            problem = ("anchor record is not an anchor row"
                       if record.get("kind") != "anchor" else
                       _agrees_problem(record, chain, locator))
    else:
        problem = f"unknown commitment source {source!r}"
    if problem:
        return ClaimResult("commitment", FAILS, problem), False
    return _corroborate(commitment, source, anchor_digest, checkpoint_dir)


def _corroborate(commitment: dict, source: str, anchor_digest: str | None,
                  checkpoint_dir: Path | None) -> tuple[ClaimResult, bool]:
    """Compare the (issuer-signed) commitment with what the verifier brought."""
    notes: list[str] = []
    if source == "anchor_ledger":
        if checkpoint_dir is not None:
            # The requested comparison cannot be performed: never report it
            # as passed.
            return ClaimResult(
                "commitment", FAILS,
                "--checkpoint-dir was given but this receipt is committed by "
                "the anchor ledger, not a checkpoint file; no checkpoint "
                "comparison is possible"), False
        notes.append("the anchor ledger lives beside the log and is signed by the "
                     "same key; it is the issuer's own commitment, not an "
                     "independent one")
        return ClaimResult("commitment", HOLDS,
                           "tip committed by the issuer's anchor ledger", notes), False
    digest = str(commitment.get("raw_sha256") or "")
    external = False
    wanted = (anchor_digest or "").strip().lower()
    if wanted:
        if wanted != digest:
            return ClaimResult(
                "commitment", FAILS,
                "the out-of-band checkpoint digest does not match this receipt's "
                "checkpoint (history was re-committed after the digest was "
                "published, or the receipt is not from this deployment)"), False
        external = True
        notes.append(f"checkpoint sha256 matches the out-of-band digest {wanted[:12]}...")
    if checkpoint_dir is not None:
        filename = commitment.get("filename")
        if not isinstance(filename, str) or not _CHECKPOINT_FILE_RE.fullmatch(filename):
            return ClaimResult(
                "commitment", FAILS,
                "the receipt names an invalid checkpoint filename"), False
        try:
            root = Path(checkpoint_dir).expanduser().resolve(strict=True)
            if not root.is_dir():
                raise ValueError("checkpoint path is not a directory")
            path = root / filename
            # The exact filename grammar excludes path separators.  The stable
            # reader below additionally rejects symlinks, reparse points,
            # non-regular files, hard links, races, and files over 64 KiB.
            if path.parent != root:
                raise ValueError("checkpoint path escapes the selected directory")
            raw = _stable_read_regular_file(path, maximum_bytes=_MAX_CHECKPOINT_BYTES)
            on_disk = hashlib.sha256(raw).hexdigest()
        except (OSError, ValueError) as e:
            return ClaimResult("commitment", FAILS,
                               f"cannot safely read the checkpoint file {filename}: {e}"), False
        if on_disk != digest:
            return ClaimResult(
                "commitment", FAILS,
                f"the checkpoint file {filename} on disk differs from the one "
                "the receipt embeds"), False
        notes.append(
            f"checkpoint file {filename} on disk is byte-identical, but the "
            "issuer's mutable directory is not independent anchoring evidence"
        )
    if not external:
        notes.append("nothing external was supplied to compare the checkpoint "
                     "against; re-run with a retained --anchor-digest to reach "
                     "depth 'anchored'")
    return ClaimResult(
        "commitment", HOLDS,
        f"tip committed by signed checkpoint #{commitment.get('sequence')}", notes), external


# ---- top level --------------------------------------------------------------

def _structural_problem(receipt: object,
                        trusted: dict[str, list[_TrustedKey]], *,
                        verification_time: float,
                        expected_version: int = SCHEMA_VERSION) -> str | None:
    if not isinstance(receipt, dict):
        return "receipt is not a JSON object"
    if receipt.get("kind") != RECEIPT_KIND:
        return f"not a {RECEIPT_KIND} (kind={receipt.get('kind')!r})"
    version = receipt.get("schema_version")
    if type(version) is not int or version != expected_version:
        # Refuse rather than guess: a newer receipt may carry checks this
        # verifier does not know how to run.
        return (f"receipt schema version {version!r} is not {expected_version} "
                "(use the verifier shipped with the receipt)")
    if not _have_crypto():
        return "the 'cryptography' package is required to verify"
    sig = receipt.get("signature")
    if not isinstance(sig, dict) or not sig.get("sig"):
        return "receipt is unsigned"
    if not trusted:
        return ("a trusted public key is required: a key read out of the receipt "
                "proves only that somebody signed it, not who")
    if _timestamp(receipt.get("issued_at")) is None:
        return "the receipt's issued_at is missing or not a finite timestamp"
    embedded = str(sig.get("pubkey") or "").strip().lower()
    try:
        embedded_id = key_id_of(embedded)
    except (TypeError, ValueError):
        return "the receipt's embedded signing key is malformed"
    if sig.get("key_id") != embedded_id:
        return "the receipt's signing key_id does not match its public key"
    policy = _trusted_at(
        trusted.get(embedded_id) or [], verification_time, embedded,
    )
    if policy is None:
        return "the receipt's signing key is not a trusted key (provenance fail)"
    try:
        canonical = canonical_bundle_bytes(receipt)
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return "receipt contents cannot be canonicalized safely"
    if not verify_ed25519(embedded, str(sig.get("sig")), canonical):
        return "signature does not verify over the receipt contents"
    return None


def verify(receipt: dict, *, trusted_keys, historical_keys=None,
           checkpoint_keys=None, anchor_digest: str | None = None,
           checkpoint_dir: Path | str | None = None,
           require_depth: str | None = None,
           now: float | None = None) -> VerifyResult:
    """Check a receipt against out-of-band keys, optionally corroborating it.

    ``ok`` is True only when the envelope verifies against a trusted key AND no
    claim FAILS. A receipt that is authentic but uncommitted is ``ok=True`` at
    depth ``signed``: it proves the issuer recorded the decision, and nothing
    about whether the log it sits in has since been rewritten. Read the depth.
    """
    verification_time = _timestamp(time.time() if now is None else now)
    if verification_time is None:
        return VerifyResult(False, DEPTH_NONE,
                            "verification time must be a finite numeric timestamp")
    issuer_trusted = _normalise_keys(trusted_keys)
    historical_trusted = _normalise_keys(historical_keys)
    evidence_trusted = {
        key_id: list(policies) for key_id, policies in issuer_trusted.items()
    }
    for key_id, policies in historical_trusted.items():
        evidence_trusted.setdefault(key_id, []).extend(policies)
    checkpoint_trusted = (
        _normalise_keys(checkpoint_keys)
        if checkpoint_keys is not None else issuer_trusted
    )
    problem = _receipt_limits_problem(receipt)
    if problem:
        return VerifyResult(False, DEPTH_NONE, problem)
    if isinstance(receipt, dict):
        version = receipt.get("schema_version")
        if type(version) is not int or version not in (
            LEGACY_SCHEMA_VERSION,
            SCHEMA_VERSION,
        ):
            return VerifyResult(
                False,
                DEPTH_NONE,
                f"unsupported receipt schema version {version!r}",
            )
    else:
        # Preserve the established structural error for non-object inputs.
        version = SCHEMA_VERSION
    problem = _structural_problem(
        receipt,
        issuer_trusted,
        verification_time=verification_time,
        expected_version=version,
    )
    if problem:
        return VerifyResult(False, DEPTH_NONE, problem)

    if version == LEGACY_SCHEMA_VERSION:
        claims = [
            _check_row(receipt, evidence_trusted),
            _check_legacy_claim(receipt),
            _check_chain(receipt, evidence_trusted),
        ]
    else:
        claims = [
            _check_row(receipt, evidence_trusted),
            _check_claim(receipt),
            _check_disclosure(receipt),
            _check_execution_pair(receipt, evidence_trusted),
            _check_chain(receipt, evidence_trusted),
        ]
    commitment, external = _check_commitment(
        receipt, evidence_trusted, checkpoint_trusted,
        verification_time=verification_time, anchor_digest=anchor_digest,
        checkpoint_dir=Path(checkpoint_dir) if checkpoint_dir else None)
    claims.append(commitment)

    findings: list[str] = []
    custody = _as_dict(receipt.get("issuer")).get("key_custody")
    if custody == "colocated":
        findings.append("the issuer's signing key is kept on the same host as the "
                        "log: this is integrity against accidental edits, not "
                        "tamper-evidence against an actor who can read that key")
    elif custody == "offhost":
        findings.append("the issuer reports an externally supplied signing key; "
                        "the historical offhost label does not establish isolated "
                        "signing: injected or KMS-unwrapped private keys remain "
                        "available to the local signing process")
    if any(
        policy.not_before is not None
        or policy.not_after is not None
        or policy.revoked_at is not None
        for policies in evidence_trusted.values()
        for policy in policies
    ):
        findings.append(
            "audit-row key-window checks use timestamps inside issuer-signed rows; "
            "they establish consistency with the signed evidence, not independently "
            "trusted event time"
        )
    if version == LEGACY_SCHEMA_VERSION:
        findings.append(
            "legacy schema-v1 claim semantics are preserved for historical "
            "compatibility; a v1 tool_call row predates v2 completion pairing"
        )
    findings.append("a receipt is point-in-time: a later lawful erasure re-signs "
                    "the day-file, after which the live log will not match this "
                    "receipt even though the receipt remains self-consistent")

    failed = [c.name for c in claims if c.status == FAILS]
    if failed:
        return VerifyResult(False, DEPTH_NONE if "row_integrity" in failed else DEPTH_SIGNED,
                            f"claim(s) FAILED: {', '.join(failed)}", claims, findings)
    chained = any(c.name == "chain_linkage" and c.status == HOLDS for c in claims)
    committed = commitment.status == HOLDS
    if chained and committed and external:
        depth = DEPTH_ANCHORED
    elif chained and committed:
        depth = DEPTH_CHAINED
    else:
        depth = DEPTH_SIGNED
    held = sum(1 for c in claims if c.status == HOLDS)
    requested = require_depth
    if anchor_digest is not None:
        requested = DEPTH_ANCHORED
    if checkpoint_dir is not None and commitment.status != HOLDS:
        return VerifyResult(
            False, depth,
            "the requested checkpoint file comparison did not hold",
            claims, findings,
        )
    if requested not in (None, DEPTH_SIGNED, DEPTH_CHAINED, DEPTH_ANCHORED):
        return VerifyResult(False, depth, f"unknown required depth {requested!r}",
                            claims, findings)
    depth_rank = {
        DEPTH_NONE: 0, DEPTH_SIGNED: 1, DEPTH_CHAINED: 2, DEPTH_ANCHORED: 3,
    }
    if requested is not None and depth_rank[depth] < depth_rank[requested]:
        return VerifyResult(
            False, depth,
            f"verification reached depth {depth!r}, below required {requested!r}",
            claims, findings,
        )
    return VerifyResult(
        True, depth,
        f"signature verified against a trusted key; {held} of {len(claims)} "
        "claim(s) affirmatively hold", claims, findings)


_STATUS_MARK = {HOLDS: "HOLDS", FAILS: "FAILS", INDETERMINATE: "INDET",
                NOT_APPLICABLE: "N/A  "}


def format_report(result: VerifyResult) -> str:
    """The human-readable verdict."""
    width = 74
    lines = ["=" * width,
             "  LIGHTWORK TRUST RECEIPT -- INDEPENDENT VERIFICATION",
             "=" * width]
    verdict = "VERIFIED" if result.ok else "REJECTED"
    lines.append(f"  result: {verdict}   (depth: {result.depth})")
    lines.append(f"  {result.reason}")
    if result.claims:
        lines.append("-" * width)
        for c in result.claims:
            lines.append(f"  [{_STATUS_MARK.get(c.status, c.status)}]  "
                         f"{c.name:20}  {c.detail}")
            for note in c.notes:
                lines.append(f"           - {note}")
    if result.findings:
        lines.append("-" * width)
        for f in result.findings:
            lines.append(f"  ! {f}")
    lines.append("=" * width)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="trust_receipt_verify",
        description="Independently verify a Lightwork trust receipt.")
    ap.add_argument("receipt", help="path to the receipt JSON")
    ap.add_argument("--key", action="append", default=[], metavar="HEX",
                    help="a CURRENT trusted receipt-issuer Ed25519 public key "
                         "obtained OUT OF BAND (repeatable)")
    ap.add_argument("--history-key", action="append", default=[], metavar="HEX",
                    help="a retired key trusted only for historical audit rows; "
                         "it cannot authorize a new receipt envelope")
    ap.add_argument("--checkpoint-key", action="append", default=[], metavar="HEX",
                    help="a current checkpoint-authority key (defaults to the "
                         "current receipt issuer keys)")
    ap.add_argument("--anchor-digest", default=None, metavar="SHA256",
                    help="the published sha256 of the checkpoint file this "
                         "receipt's tip was committed under")
    ap.add_argument("--checkpoint-dir", default=None, metavar="DIR",
                    help="directory holding the issuer's checkpoint files, to "
                         "compare the embedded checkpoint against on-disk bytes")
    ap.add_argument("--require-depth", choices=(DEPTH_SIGNED, DEPTH_CHAINED,
                                                DEPTH_ANCHORED), default=None,
                    help="reject a valid receipt that does not reach this depth; "
                         "--anchor-digest automatically requires 'anchored'")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    try:
        receipt = load_receipt(args.receipt)
    except (OSError, ValueError) as e:
        print(f"cannot read receipt: {e}", file=sys.stderr)
        return 2
    try:
        result = verify(
            receipt,
            trusted_keys=args.key,
            historical_keys=args.history_key,
            checkpoint_keys=args.checkpoint_key or None,
            anchor_digest=args.anchor_digest,
            checkpoint_dir=args.checkpoint_dir,
            require_depth=args.require_depth,
        )
    except Exception:
        print("verification could not be completed safely", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(format_report(result))
    return 0 if result.ok else 1


__all__ = [
    "CHECKPOINT_SCHEMA", "DEPTH_ANCHORED", "DEPTH_CHAINED", "DEPTH_NONE",
    "DEPTH_SIGNED", "FAILS", "HOLDS", "INDETERMINATE", "NOT_APPLICABLE",
    "RECEIPT_KIND", "SCHEMA_VERSION", "TOOL_CALL_COMMITMENT_ALGORITHM",
    "ClaimResult", "VerifyResult",
    "audit_row_hash", "canonical_bundle_bytes", "derive_claim", "format_report",
    "key_id_of", "load_receipt", "main", "tool_call_commitment", "verify",
    "verify_ed25519",
]


if __name__ == "__main__":  # pragma: no cover -- standalone entry point
    sys.exit(main())
