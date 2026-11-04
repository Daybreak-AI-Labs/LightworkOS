"""A diverse archive of high-performing agent configs.

Naive self-improvement converges to a local optimum and stalls (the "plateau
problem"). The published fix (Darwin Gödel Machine, quality-diversity methods)
is to keep an *archive* of diverse high performers and branch from across it,
not just from the single best. This is that archive, restricted to **config**
candidates (dicts) -- no code, so it's safe to keep and sample.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import random
import threading
from dataclasses import dataclass, field
from pathlib import Path

_SCHEMA_VERSION = 4
_LEGACY_ENVELOPE_VERSION = 2
_FULL_ID_ENVELOPE_VERSION = 3
_MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_CAPACITY = 10_000
_archive_write_lock = threading.Lock()


class ArchiveIntegrityError(ValueError):
    """Persisted archive is malformed, inconsistent, or fails its checksum."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False)


def _payload_digest(payload: dict) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _validate_config_value(value: object, *, depth: int = 0) -> None:
    """Require a stable JSON value instead of identity-by-``str(object)``.

    The old ``default=str`` hash let unrelated Python objects collide on their
    display text and let tuples silently turn into lists after persistence.  A
    config identity must describe the exact durable value the next process sees.
    """
    if depth > 64:
        raise ValueError("candidate config exceeds the maximum nesting depth")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("candidate config numbers must be finite")
        return
    if isinstance(value, list):
        for item in value:
            _validate_config_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("candidate config keys must be strings")
        for item in value.values():
            _validate_config_value(item, depth=depth + 1)
        return
    raise ValueError("candidate config must contain only canonical JSON values")


def _config_json(config: dict) -> str:
    if not isinstance(config, dict):
        raise ValueError("candidate config must be an object")
    _validate_config_value(config)
    try:
        # Preserve the historical serialization (including its whitespace) so
        # every legacy 12-hex id is the prefix of the new full digest.
        blob = json.dumps(config, sort_keys=True, allow_nan=False)
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("candidate config is not canonical JSON") from exc
    if len(blob.encode("utf-8")) > _MAX_CONFIG_BYTES:
        raise ValueError("candidate config exceeds the size limit")
    return blob


def _config_id(config: dict) -> str:
    return hashlib.sha256(_config_json(config).encode("utf-8")).hexdigest()


def _legacy_config_id(config: dict) -> str:
    return _config_id(config)[:12]


def _candidate_from_archive(
    raw: object, *, allow_legacy_id: bool, require_id: bool,
) -> Candidate:
    if not isinstance(raw, dict) or set(raw) - {"config", "score", "id"}:
        raise ValueError("candidate entry is malformed")
    config = raw.get("config")
    if not isinstance(config, dict):
        raise ValueError("candidate entry is malformed")
    raw_id = raw.get("id")
    if require_id and (not isinstance(raw_id, str) or not raw_id):
        raise ValueError("candidate id is missing")
    if raw_id is not None and not isinstance(raw_id, str):
        raise ValueError("candidate id must be a string")

    candidate = Candidate(config=dict(config), score=raw.get("score", 0.0))
    if not raw_id or hmac.compare_digest(raw_id, candidate.id):
        return candidate
    if (allow_legacy_id and len(raw_id) == 12
            and hmac.compare_digest(raw_id, _legacy_config_id(candidate.config))):
        # Migration is in memory only. The next save writes schema v3 and the
        # complete digest, so no newly written archive perpetuates truncation.
        return candidate
    raise ValueError("candidate id does not match its config")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"archive contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def _candidate_payload(candidate: Candidate) -> dict:
    """Snapshot a candidate and re-bind its id to those exact persisted bytes."""
    if not isinstance(candidate, Candidate):
        raise ValueError("archive candidates must be Candidate instances")
    blob = _config_json(candidate.config)
    computed = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    if (not isinstance(candidate.id, str)
            or not hmac.compare_digest(candidate.id, computed)):
        raise ValueError("candidate id does not match its config")
    if (not isinstance(candidate.score, (int, float))
            or isinstance(candidate.score, bool)
            or not math.isfinite(float(candidate.score))):
        raise ValueError("candidate score must be finite and numeric")
    return {
        "config": json.loads(blob),
        "score": float(candidate.score),
        "id": computed,
    }


@dataclass
class Candidate:
    config: dict
    score: float = 0.0
    id: str = ""

    def __post_init__(self) -> None:
        blob = _config_json(self.config)
        # Detach nested mutable input and normalize to the exact JSON value the
        # archive persists. Identity never depends on caller-owned references.
        self.config = json.loads(blob)
        try:
            self.score = float(self.score)
        except (TypeError, ValueError) as exc:
            raise ValueError("candidate score must be numeric") from exc
        if not math.isfinite(self.score):
            raise ValueError("candidate score must be finite")
        computed = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        if self.id and self.id != computed:
            raise ValueError("candidate id does not match its config")
        self.id = computed

    def validate_identity(self) -> None:
        """Fail if mutable candidate state diverged from its content address."""
        if (not isinstance(self.id, str) or len(self.id) != 64
                or any(ch not in "0123456789abcdef" for ch in self.id)
                or not hmac.compare_digest(self.id, _config_id(self.config))):
            raise ValueError("candidate id does not match its config")
        if not isinstance(self.score, (int, float)) or isinstance(self.score, bool):
            raise ValueError("candidate score must be numeric")
        if not math.isfinite(float(self.score)):
            raise ValueError("candidate score must be finite")


@dataclass
class Archive:
    """Bounded, score-ranked, diversity-aware archive of config candidates.

    ``capacity`` caps the archive; when full, eviction keeps the best performers
    AND a spread of diverse ones, so the population doesn't collapse onto one
    lineage (which is what causes plateaus).
    """
    capacity: int = 50
    candidates: list[Candidate] = field(default_factory=list)
    # Only this exact current best crossed an independent promotion boundary.
    # Development archives deliberately carry None and cannot be adopted.
    confirmed_candidate_id: str | None = None

    def __post_init__(self) -> None:
        if (not isinstance(self.capacity, int) or isinstance(self.capacity, bool)
                or not 1 <= self.capacity <= _MAX_CAPACITY):
            raise ValueError(
                f"archive capacity must be an integer in [1, {_MAX_CAPACITY}]")
        if not isinstance(self.candidates, list) or any(
                not isinstance(candidate, Candidate) for candidate in self.candidates):
            raise ValueError("archive candidates must be Candidate instances")
        self._validate_candidates()

    def _validate_candidates(self, *, require_capacity: bool = True) -> None:
        if not isinstance(self.candidates, list):
            raise ValueError("archive candidates must be a list")
        transient_limit = _MAX_CAPACITY + (0 if require_capacity else 1)
        if len(self.candidates) > transient_limit:
            raise ValueError("candidate collection exceeds the archive limit")
        if require_capacity and len(self.candidates) > self.capacity:
            raise ValueError("candidate collection exceeds archive capacity")
        seen: set[str] = set()
        for candidate in self.candidates:
            if not isinstance(candidate, Candidate):
                raise ValueError("archive candidates must be Candidate instances")
            candidate.validate_identity()
            if candidate.id in seen:
                raise ValueError("archive contains duplicate candidate ids")
            seen.add(candidate.id)
        if self.confirmed_candidate_id is not None:
            if (not isinstance(self.confirmed_candidate_id, str)
                    or len(self.confirmed_candidate_id) != 64
                    or any(ch not in "0123456789abcdef"
                           for ch in self.confirmed_candidate_id)
                    or not self.candidates):
                raise ValueError("archive confirmation marker is invalid")
            best = max(self.candidates, key=lambda item: item.score)
            if not hmac.compare_digest(best.id, self.confirmed_candidate_id):
                raise ValueError(
                    "archive confirmation marker does not identify the current best")

    def add(self, candidate: Candidate) -> Candidate:
        """Insert (or update if a better score for the same config arrives)."""
        self._validate_candidates()
        if not isinstance(candidate, Candidate):
            raise ValueError("archive candidates must be Candidate instances")
        candidate.validate_identity()
        for existing in self.candidates:
            if existing.id == candidate.id:
                if candidate.score > existing.score:
                    self.confirmed_candidate_id = None
                    existing.score = candidate.score
                return existing
        self.confirmed_candidate_id = None
        self.candidates.append(candidate)
        self._evict_if_needed()
        return candidate

    def best(self) -> Candidate | None:
        self._validate_candidates()
        return max(self.candidates, key=lambda c: c.score) if self.candidates else None

    def mark_confirmed(self, candidate_id: str) -> Candidate:
        """Qualify the exact current best for publication/adoption."""
        self._validate_candidates()
        best = self.best()
        if (best is None or not isinstance(candidate_id, str)
                or not hmac.compare_digest(best.id, candidate_id)):
            raise ValueError("only the current archive best may be marked confirmed")
        self.confirmed_candidate_id = best.id
        return best

    def confirmed_best(self) -> Candidate | None:
        """Return the promotion-qualified best, or None for development state."""
        self._validate_candidates()
        if self.confirmed_candidate_id is None:
            return None
        return self.best()

    def sample(self, rng: random.Random | None = None) -> Candidate | None:
        """Sample a parent weighted by score (softmax-ish), so exploration
        favors good lineages without ignoring the diverse tail."""
        self._validate_candidates()
        if not self.candidates:
            return None
        rng = rng or random
        lo = min(c.score for c in self.candidates)
        weights = [(c.score - lo) + 1e-3 for c in self.candidates]  # keep all reachable
        return rng.choices(self.candidates, weights=weights, k=1)[0]

    def diverse(self, k: int) -> list[Candidate]:
        """Return the best plus the most *config-distant* others (greedy QD).

        Picks the top scorer first, then repeatedly adds the candidate maximizing
        minimum distance to the already-chosen set -- a spread of high-performing
        but distinct configs to branch from.
        """
        self._validate_candidates()
        return self._diverse_unchecked(k)

    def _diverse_unchecked(self, k: int) -> list[Candidate]:
        if not self.candidates or k <= 0:
            return []
        chosen = [max(self.candidates, key=lambda candidate: candidate.score)]
        pool = [c for c in self.candidates if c.id != chosen[0].id]
        while pool and len(chosen) < k:
            # Break config-distance ties by score so eviction can't drop a
            # stronger candidate in favour of a weaker equidistant one
            # (preserving the "keeps the best performers" guarantee).
            nxt = max(
                pool,
                key=lambda c: (
                    min(self.config_distance(c.config, s.config) for s in chosen),
                    c.score,
                ),
            )
            chosen.append(nxt)
            pool.remove(nxt)
        return chosen

    def _evict_if_needed(self) -> None:
        if len(self.candidates) <= self.capacity:
            return
        self._validate_candidates(require_capacity=False)
        # Keep a diverse high-performing subset; drop the rest.
        keep = self._diverse_unchecked(self.capacity)
        keep_ids = {c.id for c in keep}
        self.candidates = [c for c in self.candidates if c.id in keep_ids]

    @staticmethod
    def config_distance(a: dict, b: dict) -> float:
        """Normalized distance: fraction of keys whose values differ."""
        keys = set(a) | set(b)
        if not keys:
            return 0.0
        differing = sum(1 for k in keys if a.get(k) != b.get(k))
        return differing / len(keys)

    # -- persistence: a continuous evolution loop accumulates across rounds/runs --
    def to_dict(self) -> dict:
        self._validate_candidates()
        payload = {
            "capacity": self.capacity,
            "candidates": [_candidate_payload(candidate)
                           for candidate in self.candidates],
            "confirmed_candidate_id": self.confirmed_candidate_id,
        }
        return {
            "schema_version": _SCHEMA_VERSION,
            "payload": payload,
            # Detect partial/manual mutation. This is an integrity checksum, not
            # an authenticity signature; persisted scores are still re-measured
            # before a resumed search is allowed to use them.
            "sha256": _payload_digest(payload),
        }

    @classmethod
    def from_dict(cls, data: dict) -> Archive:
        if not isinstance(data, dict):
            raise ArchiveIntegrityError("archive root must be an object")
        schema: int | None
        if "schema_version" in data:
            if set(data) != {"schema_version", "payload", "sha256"}:
                raise ArchiveIntegrityError("archive integrity envelope is malformed")
            schema = data.get("schema_version")
            if (not isinstance(schema, int) or isinstance(schema, bool)
                    or schema not in {
                        _LEGACY_ENVELOPE_VERSION,
                        _FULL_ID_ENVELOPE_VERSION,
                        _SCHEMA_VERSION,
                    }):
                raise ArchiveIntegrityError("unsupported archive schema version")
            payload = data.get("payload")
            digest = data.get("sha256")
            expected_fields = (
                {"capacity", "candidates", "confirmed_candidate_id"}
                if schema == _SCHEMA_VERSION else {"capacity", "candidates"}
            )
            if (not isinstance(payload, dict) or set(payload) != expected_fields
                    or not isinstance(digest, str) or len(digest) != 64
                    or any(ch not in "0123456789abcdef" for ch in digest)):
                raise ArchiveIntegrityError("archive integrity envelope is incomplete")
            try:
                expected_digest = _payload_digest(payload)
            except (RecursionError, TypeError, ValueError) as exc:
                raise ArchiveIntegrityError("archive payload is not canonical JSON") from exc
            if not hmac.compare_digest(expected_digest, digest):
                raise ArchiveIntegrityError("archive checksum mismatch")
            body = payload
        else:
            schema = None
            if set(data) - {"capacity", "candidates"}:
                # Never reinterpret a damaged envelope (e.g. one whose schema
                # marker vanished) as an empty unchecked legacy archive.
                raise ArchiveIntegrityError("legacy archive body is malformed")
            # Read-only migration compatibility. A subsequent save emits the
            # checksummed envelope, and the runner never trusts these scores.
            body = data
        try:
            capacity = body.get("capacity", 50)
            if not isinstance(capacity, int) or isinstance(capacity, bool):
                raise ValueError("archive capacity must be an integer")
            raw_candidates = body.get("candidates", [])
            if not isinstance(raw_candidates, list):
                raise ValueError("candidate collection is not a list")
            if len(raw_candidates) > capacity or len(raw_candidates) > _MAX_CAPACITY:
                raise ValueError("candidate collection exceeds archive capacity")
            arch = cls(capacity=capacity)
            seen: set[str] = set()
            for raw in raw_candidates:
                candidate = _candidate_from_archive(
                    raw,
                    allow_legacy_id=schema in {None, _LEGACY_ENVELOPE_VERSION},
                    require_id=schema is not None,
                )
                if candidate.id in seen:
                    raise ValueError("archive contains duplicate candidate ids")
                seen.add(candidate.id)
                arch.candidates.append(candidate)
            if schema == _SCHEMA_VERSION:
                marker = body.get("confirmed_candidate_id")
                if marker is not None and not isinstance(marker, str):
                    raise ValueError("archive confirmation marker must be a string or null")
                arch.confirmed_candidate_id = marker
            arch._validate_candidates()
            return arch
        except (TypeError, ValueError) as exc:
            raise ArchiveIntegrityError("archive payload is invalid") from exc

    def save(self, path: str | Path) -> None:
        # Atomic write: a crash mid-write must not corrupt the archive (load()
        # would then return an empty archive, silently discarding accumulated
        # evolution state). A UNIQUE temp + os.replace also avoids a fixed-".tmp"
        # collision if two evolve invocations save concurrently.
        from maverick.file_lock import atomic_write_text, cross_process_lock
        with _archive_write_lock, cross_process_lock(path):
            serialized = json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"
            if len(serialized.encode("utf-8")) > _MAX_ARCHIVE_BYTES:
                raise ArchiveIntegrityError("archive exceeds the size limit")
            atomic_write_text(path, serialized)

    @classmethod
    def load(cls, path: str | Path) -> Archive:
        """Load a persisted archive; missing is empty, corruption fails closed."""
        p = Path(path)
        if not p.exists():
            return cls()
        if p.is_symlink() or not p.is_file():
            raise ArchiveIntegrityError("archive path is not a regular file")
        try:
            if p.stat().st_size > _MAX_ARCHIVE_BYTES:
                raise ArchiveIntegrityError("archive exceeds the size limit")
            data = json.loads(
                p.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object)
        except ArchiveIntegrityError:
            raise
        except (json.JSONDecodeError, OSError, UnicodeError, ValueError) as exc:
            raise ArchiveIntegrityError("archive cannot be read as JSON") from exc
        return cls.from_dict(data)


__all__ = ["Candidate", "Archive", "ArchiveIntegrityError"]
