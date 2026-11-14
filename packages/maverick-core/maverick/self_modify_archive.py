"""DGM lineage archive for governed code self-modification.

The Darwin-Gödel-Machine insight (arXiv:2505.22954) that beats naive hill-climbing
is an **archive of diverse ancestors** — including *worse* ones — so the search
branches from across a population and escapes the local optimum a single
best-only lineage stalls in (the "plateau problem"). ``maverick_evolve.archive``
already does this for **config** candidates (dicts, safe to keep and sample);
this is the same idea for the **code** rung, and it is deliberately separate
because code carries a heavier posture.

What is stored is a **lineage record**, never applied state: each entry is a
proposed patch's metadata plus the patch text (bounded), the scores it earned in
sandbox evaluation, its parent, its generation, and whether it was promoted or
rolled back. The archive is inert data — it is never executed, and *sampling a
parent to branch from does not promote anything*. The operable runner currently
disables persisted-parent branching until evaluator provenance is durably
partitioned; dedicated development harnesses may use an isolated archive.

Posture: this module is a passive datastore with no side effects beyond the file
it is told to persist to. It does not read config, does not gate, and is a no-op
unless the research loop (which IS off by default) constructs and feeds it. The
store lives under the maverick data dir with owner-only permissions.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import stat
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

# A patch kept in the archive is capped so a runaway diff can't bloat the store;
# beyond this the text is dropped (the metadata + digest are still kept, so the
# lineage is intact and the candidate is simply not re-derivable from the archive).
_MAX_PATCH_BYTES = 256 * 1024
_MAX_SUMMARY_CHARS = 4_000
_MAX_REASON_CHARS = 2_000
_MAX_REASONS = 64
_MAX_LINEAGE_ID_CHARS = 128
_MAX_EVIDENCE_SCOPE_CHARS = 128
_MAX_ARCHIVE_CAPACITY = 10_000
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ArchivePersistenceError(RuntimeError):
    """Raised when research lineage cannot be durably persisted."""


def _archive_file_identity(info) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        getattr(info, "st_mtime_ns", None),
    )


def _read_archive_json(path: Path):
    """Read one bounded archive without following filesystem aliases."""
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or bool(getattr(before, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise ValueError("code archive must be a single-link regular file")
    if before.st_size > _MAX_ARCHIVE_BYTES:
        raise ValueError("code archive exceeds the file-size limit")
    expected = _archive_file_identity(before)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _archive_file_identity(opened) != expected
        ):
            raise ValueError("code archive changed during open")
        chunks: list[bytes] = []
        total = 0
        while total <= _MAX_ARCHIVE_BYTES:
            chunk = os.read(fd, min(1024 * 1024, _MAX_ARCHIVE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > _MAX_ARCHIVE_BYTES:
            raise ValueError("code archive exceeds the file-size limit")
        if _archive_file_identity(os.fstat(fd)) != expected:
            raise ValueError("code archive changed during read")
    finally:
        os.close(fd)
    return json.loads(b"".join(chunks).decode("utf-8", errors="strict"))


def _patch_digest_and_size(patch: str) -> tuple[str, int]:
    """Hash UTF-8 patch bytes without allocating a second full patch copy."""
    digest = hashlib.sha256()
    size = 0
    for offset in range(0, len(patch), 16 * 1024):
        chunk = patch[offset:offset + 16 * 1024].encode("utf-8")
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _patch_sha256(patch: str) -> str:
    return _patch_digest_and_size(patch or "")[0]


def _short_id_from_digest(
    patch_sha256: str, summary: str, evidence_scope: str = "",
) -> str:
    blob = f"{summary}\0{patch_sha256}"
    if evidence_scope:
        blob += f"\0{evidence_scope}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def _short_id(patch: str, summary: str, evidence_scope: str = "") -> str:
    return _short_id_from_digest(_patch_sha256(patch), summary, evidence_scope)


def _is_lower_hex(value: str, length: int) -> bool:
    return len(value) == length and all(ch in "0123456789abcdef" for ch in value)


def _scan_serialized_strings(value) -> None:
    """DLP-scan every string that can cross the archive persistence boundary."""
    from .safety.self_modify_dlp import contains_secret_material

    if isinstance(value, str):
        if contains_secret_material(value):
            raise ValueError("code candidate contains detected secret material")
    elif isinstance(value, dict):
        for key, item in value.items():
            _scan_serialized_strings(key)
            _scan_serialized_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _scan_serialized_strings(item)


def _added_line_tokens(patch: str) -> frozenset[str]:
    """The set of tokens on ADDED lines — the signature used for lineage
    distance. Coarse on purpose: two patches that add mostly the same tokens are
    "near", so the diversity keep favours structurally distinct lineages."""
    toks: set[str] = set()
    for line in (patch or "").splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            for t in line[1:].split():
                if t:
                    toks.add(t)
    return frozenset(toks)


@dataclass
class CodeCandidate:
    """One node in the code-modification lineage.

    ``patch`` may be dropped (set to ``""``) if it exceeded the size cap or was
    never kept; ``patch_sha256`` always pins what the node represents. ``score``
    is the candidate's sandbox score (higher is better); ``baseline_score`` is
    what it was measured against. ``parent_id`` / ``generation`` record where in
    the search the node came from; ``promoted`` / ``rolled_back`` mirror the
    governed ladder's decision so the loop can prefer promoted lineages without
    discarding the informative "worse" ones.
    """

    summary: str
    patch: str = ""
    patch_sha256: str = ""
    score: float = 0.0
    baseline_score: float = 0.0
    samples: int = 0
    parent_id: str | None = None
    generation: int = 0
    promoted: bool = False
    rolled_back: bool = False
    capability_widens: bool | None = None
    reasons: tuple[str, ...] = ()
    created_at: float = 0.0
    evidence_scope: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        """Canonicalise and validate identity before retaining caller data.

        Oversized patch bodies are discarded *before* DLP scanning.  They never
        cross the archive/provider boundary, while their incrementally computed
        digest still pins lineage identity.  Bounded bodies and every other
        serialized string are scanned fail closed below.
        """
        if (type(self.samples) is not int or type(self.generation) is not int
                or type(self.promoted) is not bool
                or type(self.rolled_back) is not bool
                or (self.capability_widens is not None
                    and type(self.capability_widens) is not bool)
                or isinstance(self.score, bool)
                or isinstance(self.baseline_score, bool)
                or isinstance(self.created_at, bool)):
            raise ValueError("invalid code candidate record")
        try:
            self.summary = str(self.summary or "")
            self.patch = str(self.patch or "")
            self.patch_sha256 = str(self.patch_sha256 or "")
            self.id = str(self.id or "")
            self.parent_id = None if self.parent_id in (None, "") else str(self.parent_id)
            if isinstance(self.reasons, (str, bytes)):
                raise ValueError("invalid reasons")
            self.reasons = tuple(str(reason) for reason in (self.reasons or ()))
            self.score = float(self.score)
            self.baseline_score = float(self.baseline_score)
            self.samples = int(self.samples)
            self.generation = int(self.generation)
            self.created_at = float(self.created_at)
            self.evidence_scope = str(self.evidence_scope or "")
        except Exception as exc:
            raise ValueError("invalid code candidate record") from exc

        if len(self.summary) > _MAX_SUMMARY_CHARS:
            raise ValueError("invalid code candidate record")
        if len(self.reasons) > _MAX_REASONS or any(
                len(reason) > _MAX_REASON_CHARS for reason in self.reasons):
            raise ValueError("invalid code candidate record")
        if self.parent_id is not None and len(self.parent_id) > _MAX_LINEAGE_ID_CHARS:
            raise ValueError("invalid code candidate record")
        if len(self.evidence_scope) > _MAX_EVIDENCE_SCOPE_CHARS:
            raise ValueError("invalid code candidate record")
        if not all(math.isfinite(value) for value in (
                self.score, self.baseline_score, self.created_at)):
            raise ValueError("invalid code candidate record")
        if self.samples < 0 or self.generation < 0:
            raise ValueError("invalid code candidate record")
        if (self.capability_widens is not None
                and type(self.capability_widens) is not bool):
            raise ValueError("invalid code candidate record")

        actual_digest, patch_bytes = _patch_digest_and_size(self.patch)
        if self.patch and self.patch_sha256 and self.patch_sha256 != actual_digest:
            # A body that is present must always match its claimed digest.
            raise ValueError("code candidate identity mismatch")
        self.patch_sha256 = self.patch_sha256 or actual_digest
        expected_id = _short_id_from_digest(
            self.patch_sha256, self.summary, self.evidence_scope)
        legacy_id = expected_id[:12] if not self.evidence_scope else ""
        if self.id and self.id not in {expected_id, legacy_id}:
            raise ValueError("code candidate identity mismatch")
        self.id = self.id or expected_id

        if patch_bytes > _MAX_PATCH_BYTES:
            # Keep the lineage node, drop the oversized body (digest still pins it).
            log.info("code archive: dropping oversized patch body for %s", self.id)
            self.patch = ""

        # This also validates digest/id shape for a persisted digest-only node
        # whose intentionally omitted body cannot be recomputed on load.
        self._validated_payload()

    @property
    def improvement(self) -> float:
        return self.score - self.baseline_score

    def to_dict(self) -> dict:
        return self._validated_payload()

    def _validated_payload(self) -> dict:
        """Return a canonical, fully rescanned persistence payload.

        ``CodeCandidate`` remains mutable for archive bookkeeping.  Therefore
        construction-time checks are insufficient: callers holding a reference
        could change a field after insertion.  Every serialization revalidates
        identity and scans all strings, so contaminated state cannot be saved or
        handed to another subsystem.
        """
        if not isinstance(self.summary, str) or len(self.summary) > _MAX_SUMMARY_CHARS:
            raise ValueError("invalid code candidate record")
        if not isinstance(self.patch, str):
            raise ValueError("invalid code candidate record")
        actual_digest, patch_bytes = _patch_digest_and_size(self.patch)
        if patch_bytes > _MAX_PATCH_BYTES:
            # Mutating an already-retained record to an oversized body is not a
            # legitimate omission transition; refuse rather than silently alter
            # forensic state during serialization.
            raise ValueError("invalid code candidate record")
        _scan_serialized_strings({
            "summary": self.summary,
            "patch_sha256": self.patch_sha256,
            "parent_id": self.parent_id,
            "evidence_scope": self.evidence_scope,
            "reasons": self.reasons,
            "id": self.id,
        })
        from .safety.self_modify_dlp import contains_secret_material
        if contains_secret_material(self.patch, unified_diff=True):
            raise ValueError("code candidate contains detected secret material")
        if not isinstance(self.patch_sha256, str) or not _is_lower_hex(
                self.patch_sha256, 64):
            raise ValueError("invalid code candidate record")
        if (not isinstance(self.evidence_scope, str)
                or len(self.evidence_scope) > _MAX_EVIDENCE_SCOPE_CHARS):
            raise ValueError("invalid code candidate record")
        if self.patch and self.patch_sha256 != actual_digest:
            raise ValueError("code candidate identity mismatch")
        if (not isinstance(self.id, str)
                or not (_is_lower_hex(self.id, 32) or _is_lower_hex(self.id, 12))):
            raise ValueError("invalid code candidate record")
        expected_id = _short_id_from_digest(
            self.patch_sha256, self.summary, self.evidence_scope)
        if self.id not in {
            expected_id,
            expected_id[:12] if not self.evidence_scope else "",
        }:
            raise ValueError("code candidate identity mismatch")
        if self.parent_id is not None and (
                not isinstance(self.parent_id, str)
                or len(self.parent_id) > _MAX_LINEAGE_ID_CHARS):
            raise ValueError("invalid code candidate record")
        if not isinstance(self.reasons, (tuple, list)) or len(self.reasons) > _MAX_REASONS:
            raise ValueError("invalid code candidate record")
        if any(not isinstance(reason, str) or len(reason) > _MAX_REASON_CHARS
               for reason in self.reasons):
            raise ValueError("invalid code candidate record")
        if any(isinstance(value, bool) for value in (
                self.score, self.baseline_score, self.created_at)):
            raise ValueError("invalid code candidate record")
        try:
            finite = all(math.isfinite(float(value)) for value in (
                self.score, self.baseline_score, self.created_at))
        except (TypeError, ValueError):
            finite = False
        if not finite or type(self.samples) is not int or self.samples < 0:
            raise ValueError("invalid code candidate record")
        if type(self.generation) is not int or self.generation < 0:
            raise ValueError("invalid code candidate record")
        if (type(self.promoted) is not bool or type(self.rolled_back) is not bool
                or (self.capability_widens is not None
                    and type(self.capability_widens) is not bool)):
            raise ValueError("invalid code candidate record")

        payload = {
            "id": self.id, "summary": self.summary, "patch": self.patch,
            "patch_sha256": self.patch_sha256, "score": self.score,
            "baseline_score": self.baseline_score, "samples": self.samples,
            "parent_id": self.parent_id, "generation": self.generation,
            "promoted": self.promoted, "rolled_back": self.rolled_back,
            "capability_widens": self.capability_widens,
            "reasons": list(self.reasons), "created_at": self.created_at,
            "evidence_scope": self.evidence_scope,
        }
        _scan_serialized_strings(payload)
        return payload

    @classmethod
    def from_dict(cls, d: dict) -> CodeCandidate:
        if not isinstance(d, dict):
            raise ValueError("invalid code candidate record")
        reasons = d.get("reasons") or ()
        if not isinstance(reasons, (list, tuple)):
            raise ValueError("invalid code candidate record")
        samples = d.get("samples", 0)
        generation = d.get("generation", 0)
        promoted = d.get("promoted", False)
        rolled_back = d.get("rolled_back", False)
        capability_widens = d.get("capability_widens")
        score = d.get("score", 0.0)
        baseline_score = d.get("baseline_score", 0.0)
        created_at = d.get("created_at", 0.0)
        if (type(samples) is not int or type(generation) is not int
                or type(promoted) is not bool or type(rolled_back) is not bool
                or (capability_widens is not None
                    and type(capability_widens) is not bool)
                or any(isinstance(value, bool) for value in (
                    score, baseline_score, created_at))):
            raise ValueError("invalid code candidate record")
        return cls(
            summary=str(d.get("summary", "")), patch=str(d.get("patch", "")),
            patch_sha256=str(d.get("patch_sha256", "")),
            score=float(score),
            baseline_score=float(baseline_score),
            samples=samples,
            parent_id=(d.get("parent_id") or None),
            generation=generation,
            promoted=promoted,
            rolled_back=rolled_back,
            capability_widens=capability_widens,
            reasons=tuple(reasons),
            created_at=float(created_at),
            evidence_scope=str(d.get("evidence_scope", "")),
            id=str(d.get("id", "")),
        )


@dataclass
class CodeArchive:
    """Bounded, score-ranked, diversity-aware archive of code candidates.

    Eviction (when over ``capacity``) keeps a diverse high-performing subset —
    the best plus the most patch-distant others — so the population keeps a
    spread of lineages instead of collapsing onto the single best (which is what
    re-introduces the plateau). ``sample`` picks a parent to branch from weighted
    by score, so exploration favours strong lineages without abandoning the tail.
    """

    capacity: int = 100
    candidates: list[CodeCandidate] = field(default_factory=list)

    def __post_init__(self) -> None:
        try:
            self.capacity = int(self.capacity)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid code archive capacity") from exc
        if self.capacity <= 0 or self.capacity > _MAX_ARCHIVE_CAPACITY:
            raise ValueError("invalid code archive capacity")

    def add(self, cand: CodeCandidate) -> CodeCandidate:
        """Insert a canonical copy, or update the same id's score in place.

        The caller's mutable object is never retained.  This closes the
        mutate-after-add alias where clean data passed the initial scan and was
        changed to secret-bearing metadata before persistence.
        """
        if not isinstance(cand, CodeCandidate):
            raise ValueError("invalid code candidate record")
        # Rescan every existing record before changing archive state.  A caller
        # may have obtained an internal bookkeeping object through ``get`` or
        # ``sample`` and mutated it since the previous operation.
        for existing in self.candidates:
            existing.to_dict()
        canonical = CodeCandidate.from_dict(cand.to_dict())
        for existing in self.candidates:
            if existing.id == canonical.id:
                if canonical.score > existing.score:
                    # Evidence is one atomic comparison tuple. Never combine a
                    # new score with an older baseline/sample count.
                    existing.score = canonical.score
                    existing.baseline_score = canonical.baseline_score
                    existing.samples = canonical.samples
                    existing.reasons = canonical.reasons
                    existing.capability_widens = canonical.capability_widens
                    existing.created_at = canonical.created_at
                existing.promoted = existing.promoted or canonical.promoted
                existing.rolled_back = existing.rolled_back or canonical.rolled_back
                return existing
        self.candidates.append(canonical)
        self._evict_if_needed()
        return canonical

    def get(self, cand_id: str) -> CodeCandidate | None:
        return next((c for c in self.candidates if c.id == cand_id), None)

    def best(self) -> CodeCandidate | None:
        """The highest-scoring candidate that was not rolled back (a rolled-back
        line is a dead end — never the one to branch from as 'best')."""
        live = [c for c in self.candidates if not c.rolled_back]
        return max(live, key=lambda c: c.score) if live else None

    def mark_promoted(self, cand_id: str, *, promoted: bool = True) -> None:
        c = self.get(cand_id)
        if c is not None:
            c.promoted = promoted

    def mark_rolled_back(self, cand_id: str) -> None:
        c = self.get(cand_id)
        if c is not None:
            c.rolled_back = True

    def lineage(self, cand_id: str) -> list[CodeCandidate]:
        """The ancestry chain from the given candidate back to its root
        (self first, root last). Robust to a broken/cyclic parent link."""
        chain: list[CodeCandidate] = []
        seen: set[str] = set()
        cur = self.get(cand_id)
        while cur is not None and cur.id not in seen:
            seen.add(cur.id)
            chain.append(cur)
            cur = self.get(cur.parent_id) if cur.parent_id else None
        return chain

    def sample(self, rng: random.Random | None = None) -> CodeCandidate | None:
        """Sample a parent to branch from, weighted by score (promoted lineages
        get a small bonus). Rolled-back dead ends are excluded."""
        pool = [c for c in self.candidates if not c.rolled_back]
        if not pool:
            return None
        rng = rng or random
        lo = min(c.score for c in pool)
        weights = [(c.score - lo) + (0.1 if c.promoted else 0.0) + 1e-3 for c in pool]
        return rng.choices(pool, weights=weights, k=1)[0]

    def diverse(self, k: int) -> list[CodeCandidate]:
        """Best plus the most patch-distant others (greedy quality-diversity)."""
        if not self.candidates or k <= 0:
            return []
        chosen = [max(self.candidates, key=lambda c: c.score)]
        pool = [c for c in self.candidates if c.id != chosen[0].id]
        while pool and len(chosen) < k:
            nxt = max(
                pool,
                key=lambda c: (
                    min(self.patch_distance(c, s) for s in chosen),
                    c.score,
                ),
            )
            chosen.append(nxt)
            pool.remove(nxt)
        return chosen

    def _evict_if_needed(self) -> None:
        if len(self.candidates) <= self.capacity:
            return
        keep_ids = {c.id for c in self.diverse(self.capacity)}
        self.candidates = [c for c in self.candidates if c.id in keep_ids]

    @staticmethod
    def patch_distance(a: CodeCandidate, b: CodeCandidate) -> float:
        """Jaccard distance between the two patches' added-line token sets
        (0.0 identical adds, 1.0 fully disjoint). Identical patch digests are
        distance 0 regardless of token overlap."""
        if a.patch_sha256 and a.patch_sha256 == b.patch_sha256:
            return 0.0
        ta, tb = _added_line_tokens(a.patch), _added_line_tokens(b.patch)
        union = ta | tb
        if not union:
            return 0.0 if a.patch_sha256 == b.patch_sha256 else 1.0
        return 1.0 - (len(ta & tb) / len(union))

    # -- persistence ------------------------------------------------------
    def to_dict(self) -> dict:
        if (not isinstance(self.capacity, int) or isinstance(self.capacity, bool)
                or not 0 < self.capacity <= _MAX_ARCHIVE_CAPACITY
                or any(not isinstance(c, CodeCandidate) for c in self.candidates)):
            raise ValueError("invalid code archive record")
        payload = {"capacity": self.capacity,
                   "candidates": [c.to_dict() for c in self.candidates]}
        _scan_serialized_strings(payload)
        return payload

    @classmethod
    def from_dict(cls, data: dict) -> CodeArchive:
        if not isinstance(data, dict):
            raise ValueError("invalid code archive record")
        arch = cls(capacity=int(data.get("capacity", 100)))
        candidates = data.get("candidates", [])
        if not isinstance(candidates, list):
            raise ValueError("invalid code archive record")
        for c in candidates:
            if isinstance(c, dict) and c.get("summary") is not None:
                try:
                    arch.add(CodeCandidate.from_dict(c))
                except (TypeError, ValueError):
                    continue
        return arch

    def save(self, path: str | Path) -> None:
        """Merge and atomically persist with owner-only permissions.

        A caller must never report a successful learning pass when its lineage
        record was lost. The typed, generic exception lets privileged runners
        fail closed without echoing candidate metadata or filesystem details.
        The strict cross-process transaction prevents concurrent research runs
        from silently overwriting one another's lineage on shared state.
        """
        try:
            from .file_lock import atomic_write_text, cross_process_lock

            p = Path(path)
            # Validate caller-owned mutable state before entering the file
            # transaction. No contaminated record may influence merge state.
            self_payload = self.to_dict()
            with cross_process_lock(p, strict=True):
                try:
                    raw = _read_archive_json(p)
                except FileNotFoundError:
                    raw = None
                existing = None
                if raw is not None:
                    existing = CodeArchive.from_dict(raw)
                    raw_candidates = raw.get("candidates") if isinstance(raw, dict) else None
                    if (
                        not isinstance(raw_candidates, list)
                        or len(existing.candidates) != len(raw_candidates)
                    ):
                        raise ValueError("existing code archive is invalid")
                merged = CodeArchive(capacity=max(
                    self.capacity,
                    existing.capacity if existing is not None else self.capacity,
                ))
                if existing is not None:
                    for candidate in existing.candidates:
                        merged.add(candidate)
                incoming = CodeArchive.from_dict(self_payload)
                if len(incoming.candidates) != len(self.candidates):
                    raise ValueError("incoming code archive is invalid")
                for candidate in incoming.candidates:
                    merged.add(candidate)
                encoded = json.dumps(merged.to_dict(), indent=2, sort_keys=True)
                if len(encoded.encode("utf-8")) > _MAX_ARCHIVE_BYTES:
                    raise ValueError("code archive exceeds the file-size limit")
                atomic_write_text(p, encoded)  # writes 0600 atomically
        except Exception as exc:
            # Never echo candidate metadata or tenant-bearing paths here.
            log.warning("code archive persistence failed closed")
            raise ArchivePersistenceError(
                "code archive could not be durably persisted") from exc

    @classmethod
    def load(cls, path: str | Path) -> CodeArchive:
        """Load a persisted archive, or a fresh one if absent/corrupt."""
        p = Path(path)
        try:
            return cls.from_dict(_read_archive_json(p))
        except (
            FileNotFoundError,
            json.JSONDecodeError,
            OSError,
            TypeError,
            UnicodeDecodeError,
            ValueError,
        ):
            return cls()


__all__ = ["ArchivePersistenceError", "CodeCandidate", "CodeArchive"]
