"""Trust receipts: bearer-verifiable evidence for ONE audited decision.

An attestation bundle (``attestation.py``) proves properties of a whole
window. A trust receipt is the unit below it: a portable artifact for a single
audit row -- "tool X was denied under rule R for principal P at time T", or
"tool X ran" when a signed call/result pair supports that claim -- that a third
party can verify offline with the standalone
``trust_receipt_verify.py`` and a public key obtained out of band.

What the minter does, in order:

1. refuses if the day's chain does not verify (a receipt must never launder a
   tampered log into something that looks certified);
2. optionally publishes -- or reuses -- a signed **checkpoint** committing to
   the day's tip (``--checkpoint-dir``), the one commitment a verifier can
   compare against a digest the operator published out of band;
3. locates the row by hash, derives the claim with the *verifier's own*
   function, and by default omits unrelated later rows; an explicit disclosure
   opt-in embeds the full suffix needed to walk the legacy linear chain;
4. signs the whole receipt with this instance's audit key.

It never mutates the audit files. Publishing a checkpoint writes only to the
checkpoint directory, which must be disjoint from the audit directory.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

from . import trust_receipt_verify as _verify

RECEIPT_KIND = _verify.RECEIPT_KIND
SCHEMA_VERSION = _verify.SCHEMA_VERSION
VerifyResult = _verify.VerifyResult

_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CALL_ID_RE = re.compile(r"^[0-9a-f]{24}$")
_MAX_AUDIT_BYTES = 512 * 1024 * 1024


def _audit_root(audit_dir: Path | str | None) -> Path:
    if audit_dir is not None:
        return Path(audit_dir)
    from .paths import data_dir
    return Path(data_dir("audit"))


def _day_snapshot(path: Path, *, maximum_bytes: int = _MAX_AUDIT_BYTES,
                  ) -> tuple[str, list[str]]:
    """One stable, bounded plaintext snapshot plus its non-empty NDJSON lines."""
    from .audit.checkpoints import _stable_read_regular_file
    from .crypto_at_rest import is_sealed, unseal

    raw = _stable_read_regular_file(path, maximum_bytes=maximum_bytes)
    try:
        decoded = unseal(raw) if is_sealed(raw) else raw
        text = decoded.decode("utf-8")
    except Exception as exc:
        raise ValueError(f"cannot decode audit segment {path.name}") from exc
    return text, [line for line in text.splitlines() if line.strip()]


def _day_lines(path: Path) -> list[str]:
    """Non-empty NDJSON lines from one stable, bounded segment snapshot."""
    return _day_snapshot(path)[1]


def _hash_of(line: str) -> str | None:
    try:
        row = json.loads(line)
    except ValueError:
        return None
    return row.get("hash") if isinstance(row, dict) else None


def locate_row(audit_dir: Path | str | None, *, day: str,
               row_hash: str) -> tuple[dict, int, list[str]]:
    """The row with ``row_hash`` on ``day``: ``(row, position, lines after it)``.

    ``position`` is 1-indexed over non-empty lines, the same numbering the
    anchor ledger and checkpoints use for ``row_count``.
    """
    if not _DAY_RE.match(day):
        raise LookupError(f"day must be YYYY-MM-DD, got {day!r}")
    path = _audit_root(audit_dir) / f"{day}.ndjson"
    if not path.exists():
        raise LookupError(f"no audit day-file for {day}")
    lines = _day_lines(path)
    return _locate_in_lines(lines, row_hash=row_hash, day=day)


def _locate_in_lines(lines: list[str], *, row_hash: str, day: str,
                     ) -> tuple[dict, int, list[str]]:
    """Locate one hash inside an already stable snapshot."""
    hits = [i for i, ln in enumerate(lines) if _hash_of(ln) == row_hash]
    if not hits:
        raise LookupError(f"no row with hash {row_hash[:12]}... on {day}")
    if len(hits) > 1:
        raise LookupError(f"row hash {row_hash[:12]}... appears {len(hits)} times on {day}")
    index = hits[0]
    return json.loads(lines[index]), index + 1, lines[index + 1:]


def _execution_pair(lines: list[str], *, result_index: int, result: dict,
                    day: str) -> dict | None:
    """The unique earlier committed TOOL_CALL matching one TOOL_RESULT."""
    if result.get("kind") != "tool_result":
        return None
    call_id = result.get("call_id")
    if not isinstance(call_id, str) or not _CALL_ID_RE.fullmatch(call_id):
        return None
    matches: list[tuple[int, dict]] = []
    for index, line in enumerate(lines[:result_index]):
        try:
            candidate = json.loads(line)
        except ValueError:
            continue
        if (
            isinstance(candidate, dict)
            and candidate.get("kind") == "tool_call"
            and _verify._execution_pair_fields_match(
                result, {"call_row": candidate},
            )
        ):
            matches.append((index, candidate))
    if len(matches) != 1:
        return None
    index, call = matches[0]
    return {
        "call_row": call,
        "locator": {
            "day": day,
            "position": index + 1,
            "hash": call.get("hash"),
        },
    }


def _tip_after(row_hash: str, suffix: list[str]) -> str:
    tip = row_hash
    for line in suffix:
        tip = _hash_of(line) or tip
    return tip


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _anchor_for_day(root: Path, day: str) -> dict | None:
    """The latest anchor row for ``day`` in the co-located ledger, if any."""
    from .audit.signing import ANCHOR_FILENAME
    ledger = root / ANCHOR_FILENAME
    if not ledger.exists():
        return None
    latest = None
    for line in _day_lines(ledger):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("kind") == "anchor" and rec.get("day") == day:
            latest = rec
    return latest


def _checkpoint_commitment(root: Path, checkpoint_dir: Path | str, day: str) -> dict:
    """Publish (or reuse) the signed checkpoint that commits to ``day``'s tip."""
    from .audit.checkpoints import CHECKPOINT_SCHEMA, publish_checkpoint
    from .audit.signing import trusted_audit_public_keys
    path = publish_checkpoint(
        root, checkpoint_dir, day=day,
        trusted_pubkeys=list(trusted_audit_public_keys().values()))
    from .audit.checkpoints import _MAX_CHECKPOINT_BYTES, _stable_read_regular_file
    try:
        text = _stable_read_regular_file(
            path, maximum_bytes=_MAX_CHECKPOINT_BYTES,
        ).decode("utf-8")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("published checkpoint could not be read safely") from exc
    return {
        "source": "checkpoint", "schema": CHECKPOINT_SCHEMA, "filename": path.name,
        "sequence": json.loads(text)["checkpoint_sequence"],
        # The digest an operator publishes out of band is over the file's exact
        # bytes; the raw line is embedded so a verifier can recompute it
        # without re-serialising (the on-disk line is insertion-ordered).
        "raw_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "raw_line": text,
        "record": json.loads(text),
    }


def _commitment(root: Path, day: str, checkpoint_dir: Path | str | None) -> dict | None:
    if checkpoint_dir is not None:
        return _checkpoint_commitment(root, checkpoint_dir, day)
    if day < _today():
        anchor = _anchor_for_day(root, day)
        if anchor is not None:
            return {"source": "anchor_ledger", "record": anchor}
    return None


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("maverick-agent")
    except Exception:
        return ""


def build(*, audit_dir: Path | str | None = None, day: str, row_hash: str,
          checkpoint_dir: Path | str | None = None, include_suffix: bool = False,
          include_execution_pair: bool = False,
          now: float | None = None) -> dict:
    """Assemble an unsigned receipt for the row ``row_hash`` recorded on ``day``.

    The privacy-safe default omits later rows: those rows can contain unrelated
    principals, summaries, or incident details.  ``include_suffix=True`` is an
    explicit disclosure choice for a recipient who needs to walk this linear
    hash chain to the tip; the format cannot provide that proof without the full
    signed rows until a privacy-preserving inclusion accumulator is deployed.

    Tool-result receipts also omit their earlier call row by default, so an
    ``input_summary`` is not disclosed merely by minting evidence about a
    result. ``include_execution_pair=True`` is a separate disclosure opt-in:
    it embeds one full, size-bounded signed call row and enables the stronger
    ``executed`` / ``failed`` claim only when both rows carry the same valid
    call commitment.

    With ``checkpoint_dir`` the receipt commits to the checkpoint's tip, and
    the rows after the cited one are trimmed to that committed prefix, so a
    day that keeps growing after publication still yields a receipt whose
    chain and commitment agree.
    """
    from .audit.signing import active_key_is_offhost, verify_chain
    root = _audit_root(audit_dir)
    if not _DAY_RE.match(day):
        raise LookupError(f"day must be YYYY-MM-DD, got {day!r}")
    if not (root / f"{day}.ndjson").exists():
        # No day is not a broken day: say which, so an operator does not go
        # hunting for tampering that never happened.
        raise LookupError(f"no audit day-file for {day}")
    # Publish/reuse the commitment first. A later append is harmless: the one
    # stable snapshot below is trimmed back to the committed prefix. A rewrite
    # between publication and snapshot cannot be laundered because the prefix
    # tip comparison below fails.
    commitment = _commitment(root, day, checkpoint_dir)
    path = root / f"{day}.ndjson"
    text, lines = _day_snapshot(path)
    breaks = verify_chain(path, segment=text)
    if breaks:
        first = breaks[0]
        raise ValueError(
            f"refusing to mint from a broken chain: {first.reason} at line "
            f"{first.line_no} ({first.detail})")
    row, position, suffix = _locate_in_lines(lines, row_hash=row_hash, day=day)
    pair = None
    if include_execution_pair:
        pair = _execution_pair(
            lines, result_index=position - 1, result=row, day=day,
        )
        if row.get("kind") == "tool_result" and pair is None:
            raise ValueError(
                "no unique earlier signed call with a matching call commitment"
            )
    if commitment is not None:
        committed = int(commitment["record"].get("row_count") or 0)
        if position > committed:
            raise ValueError(
                "the commitment predates the cited row; publish a newer checkpoint")
        suffix = suffix[: committed - position]
    tip = _tip_after(row["hash"], suffix)
    if commitment is not None and commitment["record"].get("tip_hash") != tip:
        raise ValueError("the commitment does not agree with the chain on disk")
    receipt = {
        "kind": RECEIPT_KIND,
        "schema_version": SCHEMA_VERSION,
        "issued_at": now if now is not None else time.time(),
        "issuer": {
            "key_custody": "offhost" if active_key_is_offhost() else "colocated",
            "version": _version(),
        },
        "claim": _verify.derive_claim(row, execution_pair=pair),
        "row": row,
        "execution_pair": pair,
        "disclosure": {
            "cited_row_included": True,
            "suffix_rows_included": len(suffix) if include_suffix else 0,
            "execution_pair_included": pair is not None,
            "execution_pair_discloses_full_call_row": pair is not None,
        },
        "locator": {"day": day, "position": position, "hash": row["hash"]},
        "chain": {
            "suffix_ndjson": suffix if include_suffix else [],
            "tip_hash": tip,
            "row_count": position + len(suffix),
        },
        "commitment": commitment,
    }
    limits_problem = _verify._receipt_limits_problem(receipt)
    if limits_problem:
        raise ValueError(f"refusing to mint unverifiable receipt: {limits_problem}")
    return receipt


def sign(receipt: dict) -> dict:
    """Attach this instance's Ed25519 audit signature over the canonical body.

    Raises without ``cryptography``: an unsigned receipt is not a weaker
    receipt, it is not one at all.
    """
    from .audit.signing import _have_crypto, _load_or_create_keypair
    if not _have_crypto():
        raise RuntimeError(
            "trust receipts require 'cryptography' "
            "(install 'maverick-agent[audit-signing]'): receipts are always signed.")
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv, pub, key_id = _load_or_create_keypair()
    sig = ed25519.Ed25519PrivateKey.from_private_bytes(priv).sign(
        _verify.canonical_bundle_bytes(receipt))
    return {**receipt, "signature": {
        "pubkey": pub.hex(), "key_id": key_id, "sig": sig.hex()}}


def export(out_path: Path | str, **build_kwargs) -> Path:
    """Stage, audit, publish, and completion-audit one signed receipt.

    A prepared row is written before publication, so a filesystem failure never
    becomes a false ``issued`` claim.  Both audit writes are mandatory for this
    evidence-producing operation: ordinary fail-soft audit failure is surfaced
    instead of silently publishing an unrecorded bearer artifact.
    """
    receipt = sign(build(**build_kwargs))
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    from .audit import EventKind, audit_event
    from .file_lock import atomic_create_bytes, atomic_write_bytes
    body = json.dumps(receipt, indent=2, default=str)
    try:
        body_bytes = body.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("receipt cannot be encoded as valid UTF-8") from exc
    if len(body_bytes) > _verify._MAX_RECEIPT_BYTES:
        raise ValueError(
            "refusing to publish a receipt larger than the verifier's "
            f"{_verify._MAX_RECEIPT_BYTES}-byte limit"
        )
    artifact_sha256 = hashlib.sha256(body_bytes).hexdigest()
    pending = out.with_name(f".{out.name}.pending-{secrets.token_hex(12)}")
    common = {
        "day": receipt["locator"]["day"],
        "row_hash": receipt["locator"]["hash"],
        "committed": receipt["commitment"] is not None,
        "key_id": receipt["signature"]["key_id"],
        "artifact_sha256": artifact_sha256,
    }
    published = False
    retain_pending = False
    try:
        atomic_write_bytes(pending, body_bytes, mode=0o600)
        staged = _verify._stable_read_regular_file(
            pending, maximum_bytes=_verify._MAX_RECEIPT_BYTES,
        )
        if hashlib.sha256(staged).hexdigest() != artifact_sha256:
            raise RuntimeError("staged trust receipt digest did not persist")
        if not audit_event(
            EventKind.TRUST_RECEIPT_PREPARED,
            agent="trust_receipt",
            **common,
        ):
            raise RuntimeError(
                "trust receipt was staged but its preparation audit row was not written"
            )
        # Publish from the in-memory, already-hashed body with the hardened
        # exclusive-create primitive. It is handle-bound and durable
        # (WRITE_THROUGH on Windows; file+directory fsync on POSIX), never
        # follows a swapped pending pathname, and refuses to clobber an existing
        # receipt when concurrent exports target the same output path.
        try:
            atomic_create_bytes(out, body_bytes, mode=0o600)
        except FileExistsError:
            # Exclusive publication gives this failure an unambiguous meaning:
            # the caller did not publish this artifact, so its private staging
            # file is not a recovery record and may be removed below.
            raise
        except BaseException as exc:
            # Durable publication primitives can fail *after* the destination
            # name becomes visible (for example, a POSIX directory fsync or a
            # Windows FlushFileBuffers failure).  At that point absence cannot
            # be proved safely.  Preserve the byte-identical staged artifact as
            # an explicit recovery marker instead of deleting the only durable
            # evidence of the indeterminate transition.
            retain_pending = True
            if isinstance(exc, Exception):
                raise RuntimeError(
                    "trust receipt publication state is indeterminate; staged "
                    f"artifact retained at {pending} for pending recovery"
                ) from exc
            raise
        # From this point onward a recipient-visible path exists. Preserve the
        # staged recovery artifact if either the durable read-back or the ISSUED
        # audit fails; deleting it would erase the only machine-visible signal
        # that publication completed only partially.
        published = True
        published_bytes = _verify._stable_read_regular_file(
            out, maximum_bytes=_verify._MAX_RECEIPT_BYTES,
        )
        if hashlib.sha256(published_bytes).hexdigest() != artifact_sha256:
            raise RuntimeError(
                f"published trust receipt at {out} failed digest verification"
            )
        if not audit_event(
            EventKind.TRUST_RECEIPT_ISSUED,
            agent="trust_receipt",
            **common,
        ):
            raise RuntimeError(
                f"trust receipt was published at {out}, but its completion audit "
                "row was not written; treat it as pending recovery"
            )
        try:
            pending.unlink()
        except OSError:
            pass
    finally:
        if not published and not retain_pending and pending.exists():
            try:
                pending.unlink()
            except OSError:
                pass
    return out


def verify(receipt_path: Path | str, *, trusted_keys, historical_keys=None,
           checkpoint_keys=None, anchor_digest: str | None = None,
           checkpoint_dir: Path | str | None = None,
           require_depth: str | None = None,
           now: float | None = None) -> VerifyResult:
    """Verify a receipt on disk. Thin wrapper over the standalone verifier."""
    try:
        receipt = _verify.load_receipt(receipt_path)
    except (OSError, ValueError) as e:
        return VerifyResult(False, _verify.DEPTH_NONE, f"unreadable receipt: {e}")
    try:
        return _verify.verify(
            receipt,
            trusted_keys=trusted_keys,
            historical_keys=historical_keys,
            checkpoint_keys=checkpoint_keys,
            anchor_digest=anchor_digest,
            checkpoint_dir=checkpoint_dir,
            require_depth=require_depth,
            now=now,
        )
    except Exception:
        # A verifier is a verdict boundary, not a traceback oracle.  The
        # standalone implementation performs its own shape checks, but keep
        # this wrapper fail-closed if a malformed future schema finds a path
        # those checks do not yet cover.
        return VerifyResult(
            False,
            _verify.DEPTH_NONE,
            "verification could not be completed safely",
        )


def verifier_source() -> tuple[str, str]:
    """The standalone verifier's source text and its sha256, for hand-off."""
    path = Path(_verify.__file__)
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    return text, hashlib.sha256(raw).hexdigest()


__all__ = [
    "RECEIPT_KIND", "SCHEMA_VERSION", "VerifyResult", "build", "export",
    "locate_row", "sign", "verifier_source", "verify",
]
