"""Federated insight exchange: signed, shield-scanned learning between peers.

Swarm federation lets peers delegate WORK; this lets them share LESSONS.
``export_insights`` bundles the local consolidated dream insights and signs
the bundle with this instance's Ed25519 key (the audit-signing keypair, so
one identity covers both); ``import_insights`` verifies a bundle against the
operator's explicit trust anchors, Shield-scans and redacts every insight,
and merges through the same dedup/cap gate local dreaming uses.
An operator HALT is checked again at publication. A digest-only learning
record is required before imported lessons can be recalled; a separate
completion record distinguishes a published import from one left in a
prepared or uncertain state.

Poisoning posture — deliberately stricter than skill installs:

* Imports are **fail-closed**: an unsigned bundle, an unknown key, or a bad
  signature is rejected outright. There is no TOFU path; the trust anchors
  (``[dreaming] trusted_insight_pubkeys``) must be configured by the
  operator out of band.
* Only the consolidated insight TEXT crosses the boundary — never raw
  trajectories, reflexions, goals, or user content — and each text is
  secret-redacted, Shield-scanned, length-capped, and tagged with the
  peer's key id so recalled context shows its provenance.
* Transport is the operator's problem on purpose (a file they move or
  serve); this module never opens a network connection.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from .dreaming import DreamInsight, append_insights, load_insights

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
_MAX_TEXT = 400
_MAX_PEER_ID = 32
_MAX_BUNDLE_BYTES = 256 * 1024
_MAX_BUNDLE_ROWS = 100
_MAX_JSON_DEPTH = 8
_MAX_JSON_NODES = 4096
_MAX_PEER_EVIDENCE = 100
_MAX_STORE_INSIGHTS = 10_000
_MAX_BUNDLE_AGE_S = 7 * 24 * 60 * 60.0
_MAX_FUTURE_SKEW_S = 60.0
_MAX_REPLAY_ENTRIES = 10_000
_MAX_REPLAY_ENTRIES_PER_PEER = 2_000
_MAX_TRUST_ANCHORS = 1_024
_ALLOWED_KINDS = frozenset({"failure_pattern", "shared_pattern"})
_BUNDLE_KEYS = frozenset({
    "schema_version", "ts", "peer_key", "peer_key_id", "insights", "sig",
})
_SAFE_PEER_ID = re.compile(r"[^A-Za-z0-9_.:-]+")


class _BundleError(ValueError):
    """A peer bundle cannot be interpreted inside the bounded protocol."""


class _SanitizationError(RuntimeError):
    """A required content safety screen was unavailable or malformed."""


class _ImportAuditUnavailable(Exception):
    """The pre-publication learning record could not be written."""


def _canonical_bytes(ts: float, insights: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        {"schema_version": SCHEMA_VERSION, "ts": ts, "insights": insights},
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _normalise_pubkey(value: Any) -> str:
    if not isinstance(value, str):
        raise _BundleError("public key must be a hex string")
    key = value.strip().lower()
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
        raise _BundleError("public key must encode exactly 32 bytes")
    return key


def _normalise_signature(value: Any) -> str:
    if not isinstance(value, str):
        raise _BundleError("signature must be a hex string")
    sig = value.strip().lower()
    if len(sig) != 128 or any(c not in "0123456789abcdef" for c in sig):
        raise _BundleError("signature must encode exactly 64 bytes")
    return sig


def _normalise_trust_anchors(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        raise _BundleError("trusted_insight_pubkeys must be a list")
    if len(raw) > _MAX_TRUST_ANCHORS:
        raise _BundleError(
            f"trusted_insight_pubkeys exceeds {_MAX_TRUST_ANCHORS}-key limit"
        )
    anchors: list[str] = []
    for value in raw:
        key = _normalise_pubkey(value)
        if key not in anchors:
            anchors.append(key)
    return anchors


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _BundleError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise _BundleError(f"non-finite JSON number {value!r}")


def _validate_json_shape(value: Any) -> None:
    """Bound post-parse nesting/work before canonicalization or validation."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise _BundleError("JSON structure exceeds node limit")
        if depth > _MAX_JSON_DEPTH:
            raise _BundleError("JSON structure exceeds depth limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _read_bundle(path: Path | str) -> dict[str, Any]:
    with open(Path(path), "rb") as handle:
        raw = handle.read(_MAX_BUNDLE_BYTES + 1)
    if len(raw) > _MAX_BUNDLE_BYTES:
        raise _BundleError(
            f"bundle exceeds {_MAX_BUNDLE_BYTES}-byte limit"
        )
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise _BundleError("bundle is not valid UTF-8") from exc
    except _BundleError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise _BundleError(f"invalid JSON: {exc}") from exc
    _validate_json_shape(value)
    if not isinstance(value, dict):
        raise _BundleError("bundle root must be an object")
    return value


class _InsightReplayLedger:
    """Strict at-most-once claims backed only by tenant-scoped SQLite.

    The claim is committed before the insight store is touched. A crash in the
    small gap can lose an import, but can never replay evidence. That is the
    deliberate security trade-off for recallable external learning.
    """

    def __init__(self, path: Path | str | None = None):
        if path is None:
            from .paths import data_dir

            path = data_dir("dreaming", "insight_exchange_replay.sqlite3")
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        from .file_lock import (
            ensure_private_directory,
            ensure_private_file,
            harden_path_permissions,
        )

        ensure_private_directory(self.path.parent)
        existed = self.path.exists()
        if existed:
            ensure_private_file(self.path, 0o600)
        conn = sqlite3.connect(
            str(self.path), timeout=10.0, isolation_level=None,
        )
        try:
            if not existed:
                harden_path_permissions(self.path, 0o600)
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS replay_claims (
                    peer_key TEXT NOT NULL,
                    signature_hash TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (peer_key, signature_hash)
                )
            """)
            return conn
        except BaseException:
            conn.close()
            raise

    def claim(
        self, peer_key: str, sig: str, *, now: float, expires_at: float,
    ) -> bool:
        """Commit a claim; return True iff the verified bundle was seen."""
        signature_hash = hashlib.sha256(bytes.fromhex(sig)).hexdigest()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM replay_claims WHERE expires_at < ?", (now,),
            )
            seen = conn.execute(
                "SELECT 1 FROM replay_claims "
                "WHERE peer_key = ? AND signature_hash = ?",
                (peer_key, signature_hash),
            ).fetchone()
            if seen is not None:
                conn.commit()
                return True
            total = int(conn.execute(
                "SELECT COUNT(*) FROM replay_claims",
            ).fetchone()[0])
            peer_total = int(conn.execute(
                "SELECT COUNT(*) FROM replay_claims WHERE peer_key = ?",
                (peer_key,),
            ).fetchone()[0])
            if total >= _MAX_REPLAY_ENTRIES:
                raise _BundleError("replay ledger capacity reached")
            if peer_total >= _MAX_REPLAY_ENTRIES_PER_PEER:
                raise _BundleError("peer replay ledger capacity reached")
            conn.execute(
                "INSERT INTO replay_claims"
                "(peer_key, signature_hash, expires_at) VALUES (?, ?, ?)",
                (peer_key, signature_hash, expires_at),
            )
            conn.commit()
            return False
        except BaseException:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def release(self, peer_key: str, sig: str) -> None:
        """Undo a claim only when publication was refused before its write."""
        signature_hash = hashlib.sha256(bytes.fromhex(sig)).hexdigest()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM replay_claims WHERE peer_key = ? AND signature_hash = ?",
                (peer_key, signature_hash),
            )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


def trusted_pubkeys() -> list[str]:
    """Operator-configured peer trust anchors (hex Ed25519 public keys)."""
    from .config import config_source_errors, load_config

    cfg = load_config()
    errors = config_source_errors()
    if errors:
        raise RuntimeError("an active configuration source is invalid")
    if not isinstance(cfg, dict):
        raise RuntimeError("configuration root must be a table")
    dreaming = cfg.get("dreaming") or {}
    if not isinstance(dreaming, dict):
        raise RuntimeError("[dreaming] must be a table")
    return _normalise_trust_anchors(
        dreaming.get("trusted_insight_pubkeys", []),
    )


def export_insights(
    out_path: Path | str, *, path: Path | str | None = None,
    max_insights: int = 50, now: float | None = None,
) -> Path:
    """Write a signed insight bundle for a peer. Raises without crypto —
    an unsigned export would be unimportable everywhere by design."""
    from .audit.signing import _have_crypto, _load_or_create_keypair

    try:
        have_crypto = _have_crypto()
    except Exception as exc:
        raise RuntimeError("insight signing availability check failed") from exc
    if not have_crypto:
        raise RuntimeError(
            "insight export requires 'cryptography' (install "
            "'maverick-agent[audit-signing]'): bundles are always signed."
        )
    from cryptography.hazmat.primitives.asymmetric import ed25519

    if (
        isinstance(max_insights, bool)
        or not isinstance(max_insights, int)
        or not 1 <= max_insights <= _MAX_BUNDLE_ROWS
    ):
        raise ValueError(
            f"max_insights must be an integer from 1 to {_MAX_BUNDLE_ROWS}"
        )
    ts = now if now is not None else time.time()
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise ValueError("now must be a finite non-negative number")
    ts = float(ts)
    if not math.isfinite(ts) or ts < 0:
        raise ValueError("now must be a finite non-negative number")
    insights = load_insights(path) if path is not None else load_insights()
    from .memory_ownership import source_allowed
    insights = [item for item in insights if item.owner == "" and item.channel is None and item.user_id is None
                and all(source_allowed(goal_id, "") for goal_id in item.source_goal_ids)]
    rows: list[dict[str, Any]] = []
    for insight in insights[-max_insights:]:
        text = _sanitize(insight.text, shield=None)
        if text is None:
            continue
        if insight.kind not in _ALLOWED_KINDS:
            raise ValueError(f"unsupported insight kind {insight.kind!r}")
        if isinstance(insight.evidence, bool) or not isinstance(insight.evidence, int):
            raise ValueError("insight evidence must be an integer")
        row_ts = float(insight.ts)
        if not math.isfinite(row_ts) or row_ts < 0 or row_ts > ts + _MAX_FUTURE_SKEW_S:
            raise ValueError("insight timestamp is outside the export boundary")
        rows.append({
            "ts": row_ts,
            "kind": insight.kind,
            "text": text,
            "evidence": max(1, min(insight.evidence, _MAX_PEER_EVIDENCE)),
        })
    priv, pub, key_id = _load_or_create_keypair()
    sig = ed25519.Ed25519PrivateKey.from_private_bytes(priv).sign(
        _canonical_bytes(ts, rows),
    )
    bundle = {
        "schema_version": SCHEMA_VERSION,
        "ts": ts,
        "peer_key": pub.hex(),
        "peer_key_id": key_id,
        "insights": rows,
        "sig": sig.hex(),
    }
    out = Path(out_path)
    payload = json.dumps(bundle, indent=2, allow_nan=False)
    if len(payload.encode("utf-8")) > _MAX_BUNDLE_BYTES:
        raise ValueError("signed insight bundle exceeds the protocol byte limit")
    from .file_lock import atomic_write_text

    atomic_write_text(out, payload, mode=0o600)
    return out


def _safe_peer_id(peer_key: str) -> str:
    """Return a prompt-safe provenance label derived from the verified key."""
    return _SAFE_PEER_ID.sub("-", peer_key[:_MAX_PEER_ID])[:_MAX_PEER_ID] or "unknown"


def _sanitize(text: str, *, shield: Any | None) -> str | None:
    """Redact + Shield-scan one peer insight text; None = drop it."""
    if not isinstance(text, str):
        raise _SanitizationError("insight text must be a string")
    safe = text[:_MAX_TEXT]
    try:
        from .safety.secret_detector import redact as _redact
        safe, _ = _redact(safe)
        if not isinstance(safe, str):
            raise TypeError("secret detector returned non-text output")
        safe = safe[:_MAX_TEXT]
    except Exception as exc:
        raise _SanitizationError("secret detector unavailable") from exc
    try:
        from .memory_guard import injection_markers

        markers = injection_markers(safe)
        if not isinstance(markers, list):
            raise TypeError("injection detector returned a malformed result")
        if markers:
            return None
    except Exception as exc:
        raise _SanitizationError("injection detector unavailable") from exc
    if shield is not None:
        try:
            verdict = shield.scan_input(safe)
            allowed = getattr(verdict, "allowed", None)
            if allowed is False:
                return None
            if allowed is not True:
                raise TypeError("Shield verdict did not contain a boolean allowance")
        except Exception as exc:
            raise _SanitizationError("Shield scan unavailable") from exc
    safe = safe[:_MAX_TEXT]
    return safe if safe.strip() else None


def _prepare_incoming(
    rows: list[Any], *, bundle_ts: float, now: float, peer_key: str,
    shield: Any | None,
) -> list[DreamInsight]:
    if len(rows) > _MAX_BUNDLE_ROWS:
        raise _BundleError(
            f"bundle contains more than {_MAX_BUNDLE_ROWS} insights"
        )
    key_id = _safe_peer_id(peer_key)
    incoming_by_text: dict[tuple[str, str], DreamInsight] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise _BundleError(f"insight row {index} must be an object")
        text = row.get("text", "")
        if not isinstance(text, str) or len(text) > _MAX_TEXT:
            raise _BundleError(f"insight row {index} has invalid text")
        kind = row.get("kind", "failure_pattern")
        if not isinstance(kind, str) or kind not in _ALLOWED_KINDS:
            raise _BundleError(f"insight row {index} has unsupported kind")
        evidence = row.get("evidence", 1)
        if isinstance(evidence, bool) or not isinstance(evidence, int):
            raise _BundleError(f"insight row {index} has invalid evidence")
        evidence = max(1, min(evidence, _MAX_PEER_EVIDENCE))
        row_ts = row.get("ts", bundle_ts)
        if isinstance(row_ts, bool) or not isinstance(row_ts, (int, float)):
            raise _BundleError(f"insight row {index} has invalid timestamp")
        row_ts = float(row_ts)
        if (
            not math.isfinite(row_ts)
            or row_ts < 0
            or row_ts > min(now, bundle_ts) + _MAX_FUTURE_SKEW_S
        ):
            raise _BundleError(f"insight row {index} has invalid timestamp")
        safe = _sanitize(text, shield=shield)
        if safe is None:
            continue
        persisted = f"(peer {key_id}) {safe}"
        dedup_key = (kind, persisted)
        prior = incoming_by_text.get(dedup_key)
        if prior is not None:
            prior.evidence = max(prior.evidence, evidence)
            continue
        # Persist verified envelope time, not a peer-controlled historical
        # timestamp, so peers cannot manipulate pruning or recency ranking.
        incoming_by_text[dedup_key] = DreamInsight(
            ts=bundle_ts,
            kind=kind,
            domain=None,
            text=persisted,
            evidence=evidence,
            owner="",  # explicitly reviewed signed shared import; no local goal IDs inferred
        )
    return list(incoming_by_text.values())


def _validate_import_inputs(max_insights: Any, now: Any) -> float:
    if (
        isinstance(max_insights, bool)
        or not isinstance(max_insights, int)
        or not 1 <= max_insights <= _MAX_STORE_INSIGHTS
    ):
        raise _BundleError(
            f"invalid max_insights: expected an integer from 1 to "
            f"{_MAX_STORE_INSIGHTS}"
        )
    current = time.time() if now is None else now
    if isinstance(current, bool) or not isinstance(current, (int, float)):
        raise _BundleError("invalid current time")
    current = float(current)
    if not math.isfinite(current) or current < 0:
        raise _BundleError("invalid current time")
    return current


def _validate_envelope(
    bundle: dict[str, Any], anchors: list[str], *, now: float,
) -> tuple[str, str, float, list[Any]]:
    if set(bundle) - _BUNDLE_KEYS:
        raise _BundleError("malformed bundle: unknown top-level fields")
    schema = bundle.get("schema_version")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != SCHEMA_VERSION:
        raise _BundleError("malformed bundle: unsupported schema version")
    try:
        peer_key = _normalise_pubkey(bundle.get("peer_key"))
        sig = _normalise_signature(bundle.get("sig"))
    except _BundleError as exc:
        raise _BundleError(f"malformed bundle: {exc}") from exc
    ts_raw = bundle.get("ts")
    if isinstance(ts_raw, bool) or not isinstance(ts_raw, (int, float)):
        raise _BundleError("malformed bundle: bad ts")
    ts = float(ts_raw)
    if not math.isfinite(ts) or ts < 0:
        raise _BundleError("malformed bundle: bad ts")
    rows = bundle.get("insights")
    if not isinstance(rows, list):
        raise _BundleError("malformed bundle: missing peer_key/sig/insights")
    peer_key_id = bundle.get("peer_key_id", "")
    if not isinstance(peer_key_id, str) or len(peer_key_id) > 128:
        raise _BundleError("malformed bundle: bad peer_key_id")
    if ts > now + _MAX_FUTURE_SKEW_S:
        raise _BundleError("bundle timestamp is too far in the future")
    if now - ts > _MAX_BUNDLE_AGE_S:
        raise _BundleError("bundle is stale")
    if peer_key not in anchors:
        raise _BundleError(
            f"untrusted peer key {peer_key[:16]!r}: refusing to import"
        )
    return peer_key, sig, ts, rows


def _record_import_phase(
    *, phase: str, peer_key: str, bundle_sha256: str,
    signature_sha256: str, store_sha256: str, operator_ref: str,
    operator_basis: str, **counts: int,
) -> bool:
    """Record one digest-only learning phase; a refusal is never success."""
    from .audit import AuditRefused, EventKind, audit_event

    try:
        return audit_event(
            EventKind.LEARNING_UPDATE, agent="insight_exchange",
            operation="insights_import", phase=phase,
            peer_public_key=peer_key, bundle_sha256=bundle_sha256,
            signature_sha256=signature_sha256,
            store_after_sha256=store_sha256,
            operator_ref=operator_ref, operator_basis=operator_basis,
            **counts,
        ) is True
    except AuditRefused:
        return False


def _verify_bundle(
    peer_key: str, sig: str, ts: float, rows: list[Any],
) -> None:
    try:
        from .audit.signing import _have_crypto, verify_ed25519

        have_crypto = _have_crypto()
    except Exception as exc:
        raise _BundleError(f"cryptographic verifier unavailable: {exc}") from exc
    if not have_crypto:
        raise _BundleError("cryptography not installed: cannot verify the bundle")
    try:
        verified = verify_ed25519(peer_key, sig, _canonical_bytes(ts, rows))
    except Exception as exc:
        raise _BundleError(f"cryptographic verification error: {exc}") from exc
    if not verified:
        raise _BundleError("signature verification FAILED: bundle rejected")


def import_insights(
    bundle_path: Path | str, *, trusted: list[str] | None = None,
    path: Path | str | None = None, shield: Any | None = None,
    max_insights: int = 100, now: float | None = None,
    replay_path: Path | str | None = None,
    operator_ref: str = "unspecified", operator_basis: str = "unspecified",
) -> tuple[int, str]:
    """Verify + merge a peer bundle. Returns ``(imported, reason)``.

    Fail-closed: no trust anchors, an untrusted key, or a bad signature
    imports nothing. Merging goes through ``append_insights`` so peer
    lessons obey the same dedup and capacity rules as local dreams. A non-``ok``
    reason may still mean the atomic write happened when completion evidence
    failed; callers must show that state instead of claiming clean success.
    """
    try:
        anchors = _normalise_trust_anchors(
            trusted if trusted is not None else trusted_pubkeys()
        )
    except Exception as exc:
        return 0, f"trust configuration unavailable: {exc}"
    if not anchors:
        return 0, ("no trust anchors: configure [dreaming] "
                   "trusted_insight_pubkeys with the peer's public key")
    try:
        current = _validate_import_inputs(max_insights, now)
        bundle = _read_bundle(bundle_path)
        peer_key, sig, ts, rows = _validate_envelope(
            bundle, anchors, now=current,
        )
        _verify_bundle(peer_key, sig, ts, rows)
    except OSError as exc:
        return 0, f"unreadable bundle: {exc}"
    except _BundleError as exc:
        return 0, str(exc)

    # Do not consume bundle["peer_key_id"] here: older bundles included it as
    # unsigned display metadata, so a tampered bundle could smuggle arbitrary
    # prompt text into persisted provenance without invalidating the signature.
    try:
        incoming = _prepare_incoming(
            rows, bundle_ts=ts, now=current, peer_key=peer_key, shield=shield,
        )
    except _SanitizationError as exc:
        return 0, f"sanitization unavailable: {exc}"
    except _BundleError as exc:
        return 0, f"malformed bundle: {exc}"
    if not incoming:
        return 0, "bundle verified but contained no importable insights"
    from .learning_guard import Halted, check_learning_halt

    try:
        check_learning_halt("insight_exchange", "import_start")
    except Halted as exc:
        return 0, f"learning halted: {exc}"
    if replay_path is None and path is not None:
        destination = Path(path)
        replay_path = destination.parent / (
            f".{destination.name}.insight-replay.sqlite3"
        )
    ledger = _InsightReplayLedger(replay_path)
    try:
        replayed = ledger.claim(
            peer_key,
            sig,
            now=current,
            expires_at=ts + _MAX_BUNDLE_AGE_S,
        )
    except Exception as exc:
        return 0, f"replay protection unavailable: {exc}"
    if replayed:
        return 0, "bundle replay rejected"
    kwargs: dict = {"max_insights": max_insights}
    if path is not None:
        kwargs["path"] = path
    bundle_sha256 = hashlib.sha256(_canonical_bytes(ts, rows)).hexdigest()
    signature_sha256 = hashlib.sha256(bytes.fromhex(sig)).hexdigest()
    prepared_store_sha256: str | None = None

    def before_write(added: int, refreshed: int, store_sha256: str) -> None:
        nonlocal prepared_store_sha256
        # The insight-store lock is held here. A fresh HALT read and an
        # acknowledged audit row must precede the atomic publication, even if
        # HALT arrived after signature verification or replay claiming.
        check_learning_halt("insight_exchange", "import_persistence")
        if not _record_import_phase(
            phase="prepared", peer_key=peer_key,
            bundle_sha256=bundle_sha256, signature_sha256=signature_sha256,
            store_sha256=store_sha256, novel_candidates=added,
            refreshed_candidates=refreshed, operator_ref=operator_ref,
            operator_basis=operator_basis,
        ):
            raise _ImportAuditUnavailable("learning audit is unavailable")
        check_learning_halt("insight_exchange", "import_publish")
        prepared_store_sha256 = store_sha256

    try:
        written = append_insights(
            incoming, before_write=before_write, raise_on_error=True, **kwargs,
        )
    except (Halted, _ImportAuditUnavailable) as exc:
        # The callback ran before atomic publication. A refusal cannot consume
        # the only signed bundle the operator has; unlike an uncertain write,
        # this claim can safely be released for a later retry.
        try:
            ledger.release(peer_key, sig)
        except Exception:
            return 0, f"{exc}; replay claim could not be released"
        return 0, str(exc)
    except (OSError, RuntimeError):
        # The atomic writer may have published before reporting an error; keep
        # the replay claim so the same external lesson cannot be applied twice.
        return 0, "insight write outcome is uncertain; replay claim retained"
    if prepared_store_sha256 is None:
        return 0, "bundle verified but no insight change was published"
    if not _record_import_phase(
        phase="published", peer_key=peer_key,
        bundle_sha256=bundle_sha256, signature_sha256=signature_sha256,
        store_sha256=prepared_store_sha256, reported_added=written,
        operator_ref=operator_ref, operator_basis=operator_basis,
    ):
        # The prepared row still binds the intended bytes, but do not describe
        # the full audit trail as clean when the completion row is absent.
        return written, "import published but completion audit is unavailable"
    return written, "ok"


__all__ = [
    "SCHEMA_VERSION",
    "trusted_pubkeys",
    "export_insights",
    "import_insights",
]
