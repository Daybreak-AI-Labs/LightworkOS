"""Build a portable, independently verifiable attestation bundle.

The Operating Record capsule (:mod:`maverick.operating_record`) already exports
the firm's decisions signed. What it cannot do is convince somebody who trusts
nobody: :func:`operating_record.verify_capsule_integrity` checks the signature
using the public key stored *inside the capsule*, which proves the file has not
been edited since signing and says nothing whatever about who signed it. Anyone
can mint a keypair and sign anything. That is integrity; a regulator, insurer or
acquirer came for provenance.

This module builds the artifact that answers them. A bundle binds three claims
to evidence somebody else can re-derive:

1. **policy_envelope** -- every recorded governed dispatch attempt stayed inside
   the declared governance envelope. Checkable because the signed chain records
   a pre-dispatch ``tool_call`` row and the envelope names what was forbidden.
   Completion is evidenced separately by a correlated ``tool_result`` row.
2. **bounded_self_improvement** -- the learning loop never granted itself
   authority it did not already have. The bundle's distinctive claim, and the
   reason :class:`maverick.self_improvement.PromotionRecord` records *how*
   the capability gate judged each promotion: the gate always refused a widening
   change, but a receipt that omits the grading leaves "proven bounded" and
   "never checked" indistinguishable to anybody reading the ledger afterwards.
3. **authentic_history** -- the decision history is intact and complete, via
   per-day content digests, chain tips and the cross-file anchor ledger.

Three rules govern what goes in, all inherited from the consequence adapters:

*Evidence, not assertion.* A claim is made only when the bundle carries what
substantiates it. Where evidence is missing the claim is issued
``INDETERMINATE`` and stays that way -- the builder never upgrades a claim it
could not support, and an empty governance policy yields ``NOT_APPLICABLE``
rather than a vacuous pass.

*The verifier is the authority.* :mod:`maverick.attestation_verify` grades the
claims and imports nothing from maverick, so the check an auditor runs on a
laptop is the same code path, not a re-implementation that might be kinder.

*Reads only.* Building an attestation never mutates what it attests to.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from .attestation_verify import (
    BUNDLE_KIND,
    SCHEMA_VERSION,
    VerifyResult,
    format_report,
)
from .attestation_verify import verify as verify_bundle

log = logging.getLogger(__name__)

#: Audit event kinds that record a *refused* action. Counted into the envelope
#: claim as corroboration that the chokepoint was live: a window with denials in
#: it demonstrably had enforcement running.
_DENIAL_KINDS = (
    "governance_denied", "capability_denied", "shield_block", "egress_blocked",
    "autonomy_gated", "agent_trust_denied",
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _declared_envelope(observed: set[str]) -> dict[str, Any]:
    """The governance envelope as declared at issue time, plus risk levels.

    The risk classification of each observed tool is written into the bundle
    because the standalone verifier cannot call :func:`maverick.safety.tool_risk`
    -- it deliberately imports nothing from us. Putting the table inside the
    signed body makes it an attested, inspectable statement by the issuer rather
    than a hidden assumption, and the verifier labels every conclusion that
    depends on it as issuer-declared. That is the honest shape: we cannot make a
    third party trust our risk model, but we can stop them from having to guess
    what it was.
    """
    env: dict[str, Any] = {
        "deny_actions": [], "require_human_actions": [],
        "deny_min_risk": None, "require_human_min_risk": None,
        "deny_above": {}, "require_human_above": {},
        "require_fresh_human_approval": False,
        "policy_source": "unavailable",
    }
    try:
        from .governance import Policy
        policy = Policy.from_config()
    except Exception as e:
        # A policy that cannot be read is not an empty policy. Recording it as
        # unavailable keeps the verifier from reading "forbids nothing" off a
        # load failure and reporting the envelope claim as inapplicable.
        log.warning("attestation: governance policy unavailable: %s", e)
        env["policy_error"] = str(e)[:200]
        return env
    env.update({
        "deny_actions": sorted(policy.deny_actions),
        "require_human_actions": sorted(policy.require_human_actions),
        "deny_min_risk": policy.deny_min_risk,
        "require_human_min_risk": policy.require_human_min_risk,
        "deny_above": dict(sorted(policy.deny_above.items())),
        "require_human_above": dict(sorted(policy.require_human_above.items())),
        "require_fresh_human_approval": bool(policy.require_fresh_human_approval),
        "policy_source": "config",
    })
    risks: dict[str, str] = {}
    try:
        from .safety.tool_risk import tool_risk
        for name in sorted(observed):
            try:
                risks[name] = str(tool_risk(name))
            except Exception:  # pragma: no cover -- one unclassifiable tool
                continue
    except Exception as e:  # pragma: no cover -- risk table unavailable
        log.debug("attestation: risk classification skipped: %s", e)
    env["tool_risk"] = risks
    return env


def _scan_audit(audit_dir: Path,
                issued_day: str) -> tuple[list[dict], list[str], int, list[str]]:
    """Commit to every audit day-file; return (days, tools, denials, warnings).

    Each day is committed by content digest, chain tip and row count. The digest
    is over the raw on-disk bytes so a sealed (encrypted-at-rest) segment can
    still be pinned exactly, even though nobody outside the tenant can walk the
    chain inside it -- the verifier reports that limit rather than papering it.

    A day-file for ``issued_day`` or later is marked ``open``: the audit log is
    append-only and *today's file is still being written to* -- not least by this
    export, which records its own issuance. Committing to an open day as though
    it were final would make every bundle self-invalidating the moment the next
    row lands, so an open day is committed as a **prefix**: the first ``rows``
    rows and the tip at that point. Later growth is expected and does not break
    it; an edit to those first rows still does.
    """
    from .audit.sealing import segment_text as _segment_text
    from .audit.signing import _file_tip_and_count, day_files
    from .crypto_at_rest import is_sealed

    days: list[dict] = []
    tools: list[str] = []
    denials = 0
    warnings: list[str] = []
    if not audit_dir.is_dir():
        return days, tools, denials, ["audit directory does not exist"]

    for path in day_files(audit_dir):
        try:
            raw = path.read_bytes()
        except OSError as e:
            # Nothing about this file can be committed to. The verifier flags an
            # uncommitted day-file that predates issuance, so the gap surfaces
            # on the auditor's side too rather than resting on this warning.
            warnings.append(f"{path.stem}: unreadable, not committed ({e})")
            continue
        sealed = bool(is_sealed(raw))
        # The content digest is computed from the raw bytes and so is available
        # even when the chain inside them is not: it is the one commitment an
        # outside auditor can always check, and forfeiting it because a
        # decryption or parse step failed would throw away the strongest thing
        # we can offer them. Tip and row count need readable NDJSON, so they are
        # attempted separately and left null when that fails.
        entry: dict[str, Any] = {
            "day": path.stem, "sha256": hashlib.sha256(raw).hexdigest(),
            "sealed": sealed, "tip": None, "rows": None,
            "open": path.stem >= issued_day,
        }
        try:
            entry["tip"], entry["rows"] = _file_tip_and_count(path)
        except Exception as e:
            warnings.append(f"{path.stem}: chain not readable at issue time ({e})")
        days.append(entry)
        if sealed:
            warnings.append(
                f"{path.stem}: sealed at rest; a third party can confirm the "
                "bytes but cannot re-walk the chain")
        # A sealed day's actions are still scanned. The issuer holds the at-rest
        # key, so omitting them would make its OWN disclosure incomplete -- and
        # since the verifier cannot re-walk a sealed day either, an action hidden
        # in one would be invisible at both depths. Full disclosure by the
        # issuer, partial corroboration by the auditor, is the honest split.
        try:
            text = _segment_text(path) if sealed else raw.decode(
                "utf-8", errors="replace")
        except Exception as e:
            warnings.append(
                f"{path.stem}: actions not enumerable at issue time ({e}); this "
                "day's actions are absent from the envelope claim")
            continue
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict):
                continue
            kind = row.get("kind")
            if kind == "tool_call":
                name = row.get("name")
                if isinstance(name, str) and name:
                    tools.append(name)
            elif kind in _DENIAL_KINDS:
                denials += 1
    return days, tools, denials, warnings


def _scan_anchors(audit_dir: Path) -> dict[str, Any]:
    """Commit to the cross-file anchor ledger (defeats whole-day deletion)."""
    from .audit.signing import ANCHOR_FILENAME
    path = audit_dir / ANCHOR_FILENAME
    if not path.exists():
        return {"present": False}
    try:
        return {"present": True, "sha256": _sha256_file(path),
                "name": ANCHOR_FILENAME}
    except OSError as e:  # pragma: no cover
        return {"present": True, "error": str(e)[:200]}


def _scan_promotions(*, since: float | None) -> tuple[list[dict], dict, list[str]]:
    """The promotion receipts in the window, plus a digest of their ledger."""
    warnings: list[str] = []
    try:
        from .paths import data_dir
        from .self_improvement import PromotionLedger
        path = data_dir("self_improvement.json")
        if not Path(path).exists():
            return [], {"present": False}, []
        ledger = PromotionLedger(path=path)
        records = ledger.all()
    except Exception as e:
        # Fail loud in the bundle rather than quietly emitting zero promotions:
        # "no self-change was promoted" and "we could not read the ledger" are
        # opposite findings, and the first is the one an unreadable ledger would
        # otherwise masquerade as.
        log.warning("attestation: promotion ledger unavailable: %s", e)
        return [], {"present": False, "error": str(e)[:200]}, [
            f"promotion ledger unreadable: {e}"]

    receipts = [
        {
            "id": r.id, "rung": r.rung, "promoted_at": r.promoted_at,
            "rolled_back": r.rolled_back,
            "capability_evidence": r.capability_evidence,
            "capability_probe_tools": r.capability_probe_tools,
        }
        for r in records
        if since is None or r.promoted_at >= since
    ]
    commitment: dict[str, Any] = {"present": True, "path_name": Path(path).name}
    try:
        commitment["sha256"] = _sha256_file(Path(path))
    except OSError as e:  # pragma: no cover
        commitment["error"] = str(e)[:200]
    stale = [r["id"] for r in receipts if r["capability_evidence"] is None]
    if stale:
        warnings.append(
            f"{len(stale)} promotion receipt(s) predate capability grading and "
            "cannot prove authority stayed bounded")
    return receipts, commitment, warnings


def _learning_frozen() -> bool | None:
    """Whether the verifier-drift interlock is currently engaged."""
    try:
        from .calibration import learning_frozen
        return bool(learning_frozen())
    except Exception as e:  # pragma: no cover
        log.debug("attestation: calibration state unavailable: %s", e)
        return None


def build(*, audit_dir: Path | str | None = None, since: float | None = None,
          now: float | None = None) -> dict:
    """Assemble the (unsigned) attestation bundle from live evidence.

    ``since`` bounds the promotion window; audit commitments always cover every
    day-file present, because committing to a subset would let the bundle choose
    which history to be judged on.
    """
    from .paths import data_dir
    root = Path(audit_dir) if audit_dir is not None else data_dir("audit")

    ts = float(now if now is not None else time.time())
    issued_day = time.strftime("%Y-%m-%d", time.gmtime(ts))
    days, tools, denials, warnings = _scan_audit(root, issued_day)
    receipts, ledger_commit, ledger_warnings = _scan_promotions(since=since)
    warnings.extend(ledger_warnings)
    envelope = _declared_envelope(set(tools))

    return {
        "kind": BUNDLE_KIND,
        "schema_version": SCHEMA_VERSION,
        "issued_at": ts,
        "issued_day": issued_day,
        "window_since": since,
        "envelope": envelope,
        "claims": {
            # The builder records the evidence; the verifier grades it. These
            # blocks are deliberately raw observations, not verdicts -- a
            # self-graded claim is the thing a third party cannot use.
            "policy_envelope": {
                "tool_calls": sorted(set(tools)),
                "tool_call_rows": len(tools),
                "denials_recorded": denials,
            },
            "bounded_self_improvement": {
                "promotions": receipts,
                "learning_frozen": _learning_frozen(),
            },
            "authentic_history": {"day_files": len(days)},
        },
        "commitments": {
            "audit_days": days,
            "anchors": _scan_anchors(root),
            "ledger": ledger_commit,
        },
        "warnings": warnings,
    }


def sign(bundle: dict) -> dict:
    """Attach the instance's Ed25519 audit signature over the canonical body.

    Raises without ``cryptography``: an unsigned attestation is not a weaker
    attestation, it is not one at all.
    """
    from .audit.signing import _have_crypto, _load_or_create_keypair
    if not _have_crypto():
        raise RuntimeError(
            "attestation requires 'cryptography' "
            "(install 'maverick-agent[audit-signing]'): bundles are always signed.")
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from .attestation_verify import canonical_bundle_bytes
    priv, pub, key_id = _load_or_create_keypair()
    sig = ed25519.Ed25519PrivateKey.from_private_bytes(priv).sign(
        canonical_bundle_bytes(bundle))
    return {**bundle, "signature": {
        "pubkey": pub.hex(), "key_id": key_id, "sig": sig.hex()}}


def export(out_path: Path | str, *, audit_dir: Path | str | None = None,
           since: float | None = None, now: float | None = None) -> Path:
    """Build, sign and atomically write a bundle. Returns the path."""
    bundle = sign(build(audit_dir=audit_dir, since=since, now=now))
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    from .audit import EventKind, audit_event

    # A strict audit refusal must happen before the artifact is published.
    # Ordinary writer outages remain fail-soft through audit_event.
    audit_event(
        EventKind.LEARNING_UPDATE, agent="attestation",
        attestation="export", days=len(bundle["commitments"]["audit_days"]),
        key_id=bundle["signature"]["key_id"],
    )
    from .file_lock import atomic_write_text
    atomic_write_text(out, json.dumps(bundle, indent=2, default=str), mode=0o600)
    return out


def publisher_key(*, create: bool = True) -> tuple[str, str]:
    """This instance's ``(key_id, pubkey_hex)`` -- what to publish out of band.

    A verifier needs this through a channel that does not run through the
    bundle: a key page, a signed contract, an existing engagement. Handing it
    over inside the artifact it authenticates would be circular.
    """
    from .audit import signing
    if not create:
        # A read must never provision injected keys, contact KMS, or generate
        # a local keypair. Only already provisioned trust is available here.
        registry = signing.trusted_audit_public_keys()
        active = signing._active_key_id(signing._key_dir()) if registry else None
        if active and active in registry:
            return active, registry[active]
        if len(registry) == 1:
            return next(iter(registry.items()))
        raise ValueError("no unambiguous provisioned active signing key")
    from .audit.signing import _load_or_create_keypair
    _priv, pub, key_id = _load_or_create_keypair()
    return key_id, pub.hex()


def verify(bundle_path: Path | str, *, trusted_key_hex: str,
           evidence_root: Path | str | None = None) -> VerifyResult:
    """Verify a bundle on disk. Thin wrapper over the standalone verifier."""
    try:
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return VerifyResult(False, "unverified", f"unreadable bundle: {e}")
    return verify_bundle(bundle, trusted_key_hex=trusted_key_hex,
                         evidence_root=evidence_root)


def verifier_source() -> tuple[str, str]:
    """The standalone verifier's source text and its sha256.

    Exported so an auditor can be handed the checker alongside the bundle, and
    so the digest can be quoted independently -- a verifier the publisher also
    controls is only useful if its bytes can be pinned.
    """
    from . import attestation_verify
    path = Path(attestation_verify.__file__)
    text = path.read_text(encoding="utf-8")
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


__all__ = [
    "build", "export", "format_report", "publisher_key", "sign", "verify",
    "verifier_source",
]
