"""Login-time OIDC subject directory: bridge IdP identifiers to the OIDC ``sub``.

A dashboard session is keyed by the exact OIDC ``sub`` seen at login. SCIM
deprovision revokes by the IdP's SCIM attributes (``externalId`` / ``userName``
/ ``email`` / ``id``) -- but some IdPs (notably Entra/Azure AD with a
*pairwise/per-app* subject) issue a ``sub`` that equals none of those, so the
deprovision could not reach the live session. This directory closes that gap: at
every successful login it records, for the user's stable IdP identifiers, the
``sub`` actually minted into the session. SCIM deprovision then looks the
``sub`` up by those same identifiers and revokes it.

Design (matches the revocation store's discipline):

* **Privacy.** Lookup keys are ``sha256(normalized identifier)`` -- raw
  emails/usernames never touch disk. The stored value is the opaque ``sub``
  (itself the revocation key, not PII) plus a last-seen timestamp.
* **Durable + concurrent-safe.** ``<maverick_home>/oidc-subjects.json`` (0600),
  written atomically under a cross-process lock, like ``session_revocation``.
* **Bounded.** LRU-pruned to ``_MAX_ENTRIES`` by last-seen, so a long-lived
  multi-tenant deployment cannot grow the file without bound.
* **Durable retirement.** Hard-deleted SCIM identities are retained as hashed
  subject tombstones in ``oidc-retired-subjects.json``.  A freshly minted IdP
  token therefore remains denied even after the SCIM resource itself is gone.
* **Fail closed for authorization.** Login recording remains best-effort, but
  lifecycle reads and retirement writes raise on damaged state so callers can
  deny access or make the IdP retry instead of silently losing a revocation.
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections.abc import Iterable
from contextlib import ExitStack, contextmanager
from pathlib import Path

from maverick.file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from maverick.paths import maverick_home

# Cap on stored identifier->sub entries. Beyond it the oldest (by last-seen) are
# pruned, so the file stays bounded for a long-lived deployment.
_MAX_ENTRIES = 50_000
_MAX_RETIRED = 100_000
_MAX_STORE_CHARS = 4 * 1024 * 1024
_MAX_RETIRED_STORE_CHARS = 16 * 1024 * 1024

_LOCK = threading.Lock()


class SubjectDirectoryError(RuntimeError):
    """A present subject binding directory cannot be trusted."""


def _path() -> Path:
    return maverick_home() / "oidc-subjects.json"


def _retired_path() -> Path:
    return maverick_home() / "oidc-retired-subjects.json"


@contextmanager
def _locked():
    from maverick.authority_effects import authority_effect_fence

    ensure_private_directory(maverick_home())
    with ExitStack() as stack:
        stack.enter_context(authority_effect_fence())
        stack.enter_context(_LOCK)
        stack.enter_context(cross_process_lock(_path()))
        yield


def _norm(identifier: str) -> str:
    """Case/space-normalize an identifier so ``Alice@X.com`` and ``alice@x.com``
    (and the same userName with stray whitespace) hash to one key."""
    return (identifier or "").strip().casefold()


def _key(identifier: str) -> str:
    return hashlib.sha256(_norm(identifier).encode("utf-8")).hexdigest()


def _subject_key(subject: str) -> str:
    """Case-sensitive, domain-separated digest for an OIDC subject.

    Identifier keys intentionally case-fold emails/usernames. OIDC ``sub`` is
    opaque and case-sensitive, so using the identifier digest here could let a
    re-provision of one case variant clear another principal's tombstone.
    """
    value = str(subject or "").strip()
    return hashlib.sha256(b"subject\0" + value.encode("utf-8")).hexdigest()


def _reject_constant(value: str):
    raise ValueError(f"non-finite number {value!r}")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _read_json(
    path: Path,
    *,
    label: str,
    max_chars: int = _MAX_STORE_CHARS,
) -> dict | None:
    ensure_private_directory(maverick_home())
    try:
        ensure_private_file(path)
        raw = atomic_read_text(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SubjectDirectoryError(f"{label} unreadable: {exc}") from exc
    if len(raw) > max_chars:
        raise SubjectDirectoryError(f"{label} exceeds the size limit")
    try:
        decoded = json.loads(
            raw,
            parse_constant=_reject_constant,
            object_pairs_hook=_strict_object,
        )
    except (RecursionError, TypeError, ValueError) as exc:
        raise SubjectDirectoryError(f"{label} corrupt: {exc}") from exc
    if not isinstance(decoded, dict):
        raise SubjectDirectoryError(f"{label} corrupt: root must be an object")
    return decoded


def _load() -> dict:
    data = _read_json(_path(), label="subject directory")
    if data is None:
        return {}
    if not isinstance(data, dict) or len(data) > _MAX_ENTRIES:
        raise SubjectDirectoryError("subject directory corrupt: invalid root or size")
    validated: dict[str, dict[str, object]] = {}
    for key, entry in data.items():
        if len(key) != 64 or any(ch not in "0123456789abcdef" for ch in key):
            raise SubjectDirectoryError("subject directory corrupt: invalid identifier digest")
        if not isinstance(entry, dict) or set(entry) != {"sub", "ts"}:
            raise SubjectDirectoryError("subject directory corrupt: invalid binding")
        sub = entry.get("sub")
        ts = entry.get("ts")
        if not isinstance(sub, str) or not sub.strip() or sub != sub.strip() or len(sub) > 4096:
            raise SubjectDirectoryError("subject directory corrupt: invalid subject")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            raise SubjectDirectoryError("subject directory corrupt: invalid timestamp")
        timestamp = float(ts)
        if not math.isfinite(timestamp) or timestamp < 0:
            raise SubjectDirectoryError("subject directory corrupt: invalid timestamp")
        validated[key] = {"sub": sub, "ts": timestamp}
    return validated


def _load_retired() -> dict[str, int | float]:
    data = _read_json(
        _retired_path(),
        label="retired subject ledger",
        max_chars=_MAX_RETIRED_STORE_CHARS,
    )
    if data is None:
        return {}
    if set(data) != {"subjects"} or not isinstance(data.get("subjects"), dict):
        raise SubjectDirectoryError("retired subject ledger corrupt: invalid root")
    subjects = data["subjects"]
    if len(subjects) > _MAX_RETIRED:
        raise SubjectDirectoryError("retired subject ledger exceeds the entry limit")
    validated: dict[str, int | float] = {}
    for key, value in subjects.items():
        if len(key) != 64 or any(ch not in "0123456789abcdef" for ch in key):
            raise SubjectDirectoryError(
                "retired subject ledger corrupt: invalid subject digest"
            )
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SubjectDirectoryError(
                "retired subject ledger corrupt: invalid timestamp"
            )
        timestamp = float(value)
        if not math.isfinite(timestamp) or timestamp < 0:
            raise SubjectDirectoryError(
                "retired subject ledger corrupt: invalid timestamp"
            )
        validated[key] = value
    return validated


def _save_retired(subjects: dict[str, int | float]) -> None:
    if len(subjects) > _MAX_RETIRED:
        raise SubjectDirectoryError("retired subject ledger exceeds the entry limit")
    # Round-trip through the strict validator before replacing authorization
    # state, so a future caller cannot persist a malformed tombstone map.
    payload = {"subjects": dict(sorted(subjects.items()))}
    for key, value in payload["subjects"].items():
        if (
            len(key) != 64
            or any(ch not in "0123456789abcdef" for ch in key)
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            raise SubjectDirectoryError("invalid retired subject entry")
    atomic_write_text(_retired_path(), json.dumps(payload, sort_keys=True))


def _prune(data: dict) -> dict:
    if len(data) <= _MAX_ENTRIES:
        return data
    # Keep the most-recently-seen _MAX_ENTRIES by timestamp.
    kept = sorted(data.items(), key=lambda kv: kv[1].get("ts", 0.0), reverse=True)
    return dict(kept[:_MAX_ENTRIES])


def record_login(sub: str, identifiers: Iterable[str], *, at: float | None = None) -> None:
    """Record that ``sub`` was seen at login for each of ``identifiers`` (e.g.
    the OIDC ``email`` / ``preferred_username`` / ``oid`` claims). Blank
    identifiers and a blank ``sub`` are skipped. Best-effort: never raises into
    the login path."""
    s = (sub or "").strip()
    keys = {_key(i) for i in identifiers if (i or "").strip()}
    if not s or not keys:
        return
    try:
        ts = time.time() if at is None else float(at)
    except (OverflowError, TypeError, ValueError):
        return
    if not math.isfinite(ts) or ts < 0:
        return
    try:
        with _locked():
            data = _load()
            for k in keys:
                data[k] = {"sub": s, "ts": ts}
            atomic_write_text(_path(), json.dumps(_prune(data), sort_keys=True))
            # If any asserted identifier is already retired, permanently carry
            # that decision onto this exact (possibly brand-new pairwise) sub.
            # The binding is written first, so even a crash or full tombstone
            # ledger remains fail-closed through is_retired's linked lookup.
            retired = _load_retired()
            if keys & set(retired):
                subject_key = _subject_key(s)
                if subject_key not in retired and len(retired) >= _MAX_RETIRED:
                    return
                retired[subject_key] = ts
                _save_retired(retired)
    except Exception:  # pragma: no cover -- recording never blocks login
        return


def subs_in(index: dict, identifiers: Iterable[str]) -> set[str]:
    """Every ``sub`` recorded under any of ``identifiers`` within a pre-loaded
    ``index`` (see :func:`load_index`). Lets a caller that resolves many
    identifier sets in one pass (e.g. group-membership matching over every SCIM
    user) load the directory once instead of re-reading it per lookup."""
    out: set[str] = set()
    for i in identifiers:
        if not (i or "").strip():
            continue
        entry = index.get(_key(i))
        if isinstance(entry, dict) and entry.get("sub"):
            out.add(str(entry["sub"]))
    return out


def load_index() -> dict:
    """The raw identifier-hash -> {sub, ts} directory, read once. Pair with
    :func:`subs_in` to resolve many lookups without re-reading the file."""
    return _load()


def subs_for(identifiers: Iterable[str]) -> set[str]:
    """Every ``sub`` recorded at login under any of ``identifiers``. Used by SCIM
    deprovision to reach a session whose ``sub`` is in no SCIM attribute."""
    return subs_in(_load(), identifiers)


def retire(identifiers: Iterable[str], *, at: float | None = None) -> None:
    """Durably deny the identifiers and every currently bound OIDC subject.

    This is a correctness operation, not best-effort cleanup: any failure is
    raised so SCIM deprovisioning can fail and be retried. Raw identifiers are
    never stored; only their normalized SHA-256 digests are persisted.
    """
    values = {str(value).strip() for value in identifiers if str(value or "").strip()}
    if not values:
        return
    try:
        timestamp = time.time() if at is None else float(at)
    except (OverflowError, TypeError, ValueError) as exc:
        raise SubjectDirectoryError("invalid retirement timestamp") from exc
    if not math.isfinite(timestamp) or timestamp < 0:
        raise SubjectDirectoryError("invalid retirement timestamp")
    with _locked():
        bindings = _load()
        subjects = subs_in(bindings, values)
        # Retire both the identifier binding and every subject currently known
        # for it. The identifier tombstone also catches a *new* pairwise sub
        # that a lagging IdP records after hard deletion.
        keys = ({_key(value) for value in values}
                | {_subject_key(value) for value in values | subjects})
        retired = _load_retired()
        if len(set(retired) | keys) > _MAX_RETIRED:
            # Never evict an old tombstone to make room: that would resurrect a
            # deleted identity. Operators must expand/compact policy explicitly.
            raise SubjectDirectoryError("retired subject ledger exceeds the entry limit")
        for key in keys:
            retired[key] = timestamp
        _save_retired(retired)


def reinstate(
    identifiers: Iterable[str],
    *,
    linked_identifiers: Iterable[str] | None = None,
) -> None:
    """Clear retirement for an explicitly re-provisioned SCIM identity.

    OIDC subjects bound to ``linked_identifiers`` are cleared with them (all
    identifiers by default). The binding is intentionally retained across hard
    deletion so pairwise subjects can be safely reactivated only when the IdP
    provisions the identity again. Callers can restrict linked identifiers to
    immutable IdP claims so an unverified email binding cannot revive a subject.
    """
    values = {str(value).strip() for value in identifiers if str(value or "").strip()}
    if not values:
        return
    linked_values = values if linked_identifiers is None else {
        str(value).strip()
        for value in linked_identifiers
        if str(value or "").strip()
    }
    with _locked():
        bindings = _load()
        subjects = subs_in(bindings, linked_values)
        keys = ({_key(value) for value in values}
                | {_subject_key(value) for value in values | subjects})
        retired = _load_retired()
        changed = False
        for key in keys:
            if key in retired:
                changed = True
                retired.pop(key)
        if changed:
            _save_retired(retired)


def is_retired(subject: str) -> bool:
    """Whether an authenticated subject has been durably deprovisioned."""
    value = str(subject or "").strip()
    if not value:
        return False
    retired = _load_retired()
    if _subject_key(value) in retired:
        return True
    # A lagging/misconfigured IdP can mint a new pairwise sub after DELETE.
    # Login recording will bind that new sub to the retired immutable object id;
    # honor the identifier tombstone even though this exact subject was unknown
    # when the DELETE was processed.
    return any(
        entry.get("sub") == value and identifier_key in retired
        for identifier_key, entry in _load().items()
    )


def retired_check(directory: dict | None = None):
    """``check(subject)``: :func:`is_retired`'s answer, with the retired ledger
    (and ``directory``, see :func:`load_index`) read once for many subjects."""
    retired = _load_retired()
    entries = _load() if directory is None else directory
    retired_subs = {entry.get("sub") for identifier_key, entry in entries.items() if identifier_key in retired}

    def check(subject: str) -> bool:
        value = str(subject or "").strip()
        return bool(value) and (_subject_key(value) in retired or value in retired_subs)
    return check


def forget(identifiers: Iterable[str]) -> None:
    """Drop the directory entries for ``identifiers`` (e.g. after a hard SCIM
    delete). Best-effort; a re-login re-records them."""
    keys = {_key(i) for i in identifiers if (i or "").strip()}
    if not keys:
        return
    try:
        with _locked():
            data = _load()
            if any(k in data for k in keys):
                for k in keys:
                    data.pop(k, None)
                atomic_write_text(_path(), json.dumps(data, sort_keys=True))
    except Exception:  # pragma: no cover -- pruning never blocks SCIM
        return


__all__ = [
    "SubjectDirectoryError", "record_login", "subs_for", "subs_in",
    "load_index", "forget", "retire", "reinstate", "is_retired",
]
