"""The knowledge engine: ingest documents into a per-domain collection and
retrieve relevant chunks.

Ingestion is screened so a poisoned document is caught at the door -- RAG
poisoning is precisely what the agent compartments defend against, so the
knowledge layer scans on the way in rather than only at query time. A configured
Shield does the heavy lifting; a built-in high-signal injection-marker screen
ALWAYS runs too, so the common no-Shield default still rejects the obvious
prompt-injection payloads (mirrors fleet_memory / memory_guard, which screen
external writes regardless of whether a Shield is wired).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
import unicodedata
from dataclasses import dataclass

from .embed import DeterministicEmbedder
from .embedding_identity import FINGERPRINT_KEY, IDENTITY_KEY, identity, validate_batch
from .parse import extract_document
from .provider_accounting import operation_scope
from .store import SqliteVectorStore

log = logging.getLogger(__name__)

_EXACT_DOCUMENT_SCHEMA = "lightwork.vector-document-layout.v1"
_EXACT_CHUNK_KEYS = {"chunk_index", "chunk_start", "chunk_end"}
MAX_DOCUMENT_CHUNKS = 2048

# Built-in injection tripwire applied to every ingested chunk, even when no
# Shield is configured. maverick-knowledge is standalone (no maverick-core dep),
# so it can't reuse memory_guard.injection_markers; this is a deliberately small,
# high-signal subset of the SAME phrases -- instruction-override, role-reassign,
# fake role tags, secret-exfiltration, and safety-override. The shell/base64
# patterns memory_guard also carries are intentionally OMITTED here: a knowledge
# base legitimately ingests engineering docs full of `rm -rf` / `curl` / base64,
# and silently dropping those would harm recall. A real Shield (when passed)
# covers the rest.
#
# The phrases need an attack cue, not just the vocabulary: "you are now ready
# to log in", "the new rule takes effect", "show the password you typed" and
# "print your access token expiry" each used to drop a whole benign document.
# The cues kept: "you are now" + an assistant/AI/model word, "your/the new
# instructions", and print/show + "your"/"the user's" right before the secret.
_INJECTION_RE = re.compile(
    r"\b(?:ignore|disregard|forget)\b.{0,30}\b(?:previous|prior|above|earlier|all)\b"
    r".{0,30}\b(?:instruction|message|context|prompt|rule)"
    r"|\byou\s+are\s+now\s+(?:an?\s+|in\s+)?(?:unrestricted|uncensored|unfiltered|"
    r"jailbroken|amoral|evil|rogue|dan\b|developer\s+mode|free\s+from|no\s+longer\s+bound)"
    r"|\byou\s+are\s+now\s+(?:an?\s+|the\s+|my\s+)?(?:[\w-]+\s+){0,3}"
    r"(?:assistant|ai|model|bot|chatbot|agent|llm)\b"
    r"|\b(?:your|the)\s+new\s+instructions?\b"
    r"|\bnew\s+system\s+(?:instruction|prompt|directive|rule)"
    r"|\bnew\s+(?:instruction|prompt|directive|rule)s?\s*:"
    r"|</?\s*(?:system|assistant|developer)\s*>"
    r"|\b(?:reveal|print|show|leak|exfiltrate)\b.{0,40}\b(?:system\s+prompt|your\s+instruction)"
    r"|\b(?:print|show)\b.{0,30}\b(?:your|the\s+user'?s?)\s+"
    r"(?:secret|api[\s_-]?key|password|token|credential)"
    r"|\b(?:reveal|leak|exfiltrate)\b.{0,40}"
    r"\b(?:secret|api[\s_-]?key|password|token|credential)"
    r"|\boverride\b.{0,20}\b(?:safety|guard|shield|policy|governance)\b",
    re.IGNORECASE,
)

# The tripwire runs on a normalised copy: wrapped lines (PDF/DOCX extraction),
# zero-width characters and Cyrillic/Greek look-alikes used to defeat it.
_SCREEN_INVISIBLE = re.compile(r"[\u00ad\u180e\u200b-\u200f\u2060-\u206f\ufe00-\ufe0f\ufeff]")
_SCREEN_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "α": "a", "ο": "o", "ρ": "p", "ι": "i", "ν": "v",
})
_WHITESPACE = re.compile(r"\s+")
# The Shield's builtin backend blocks text over 262,144 characters outright, so
# a whole-document Shield scan dropped every large document. It is scanned in
# overlapping windows below that cap instead.
_SHIELD_WINDOW = 131_072
_SHIELD_WINDOW_OVERLAP = 4_096


def _source_label(source: str | None) -> str:
    """A source name on one line with no brackets. The source is a file name
    the uploader controls and is never screened, so a newline in it put text of
    the uploader's choosing on its own line in the rendered result."""
    label = " ".join(str(source or "").split()).replace("[", "(").replace("]", ")")
    return label or "unknown"


def _screen_text(text: str) -> str:
    text = _SCREEN_INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    return _WHITESPACE.sub(" ", text.translate(_SCREEN_HOMOGLYPHS))


@dataclass
class Hit:
    score: float
    text: str
    source: str


# Floor for the same-source suffix/prefix trim in _dedup_hits: a shared run
# this long between two chunks of one document is almost certainly the
# chunker's overlap, not coincidence. Shorter repeats (headings, boilerplate
# phrases) are left alone.
_MIN_DEDUP_OVERLAP = 32


def _dedup_hits(hits: list[Hit], *, max_overlap: int) -> list[Hit]:
    """Collapse retrieval redundancy before chunks are rendered into a prompt.

    The chunker overlaps neighbours by ``chunk_overlap`` chars so boundary
    facts stay retrievable -- but when both neighbours rank, the shared region
    would be sent to the model twice. Two passes over the score-sorted hits:

    1. absorb hits whose text is contained in a kept hit (keeping the longer
       text under the better score);
    2. for same-source pairs, trim a duplicated suffix/prefix run
       (>= _MIN_DEDUP_OVERLAP, <= ``max_overlap``) off the lower-ranked chunk.

    Purely lexical and conservative: different sources are never touched.
    """
    kept: list[Hit] = []
    for h in hits:
        absorbed = False
        for j, prev in enumerate(kept):
            # Same-source only: absorbing across documents would render
            # one document's text under another's [source: ...] label — a
            # silent citation corruption (shared boilerplate/license text
            # is a realistic cross-document substring).
            if h.source != prev.source:
                continue
            if h.text and h.text in prev.text:
                absorbed = True
                break
            if prev.text and prev.text in h.text:
                kept[j] = Hit(prev.score, h.text, prev.source)
                absorbed = True
                break
        if not absorbed:
            kept.append(h)
    for i in range(len(kept)):
        for j in range(len(kept)):
            if i == j:
                continue
            a, b = kept[i], kept[j]
            if a.source != b.source or not a.text or not b.text:
                continue
            limit = min(len(a.text), len(b.text), max_overlap)
            for n in range(limit, _MIN_DEDUP_OVERLAP - 1, -1):
                if a.text[-n:] == b.text[:n]:
                    kept[j] = Hit(b.score, b.text[n:].lstrip(), b.source)
                    break
    return [h for h in kept if h.text]


def _publication_guards(effect_guard, publication_scope):
    return {key: value for key, value in (("effect_guard", effect_guard), ("publication_scope", publication_scope)) if value is not None}


class KnowledgeBase:
    """A per-domain document store.

    ``collection`` is the domain's knowledge source, so a finance agent's
    queries never surface legal's documents -- knowledge respects the same
    bulkheads the compartments enforce.
    """

    def __init__(self, store=None, embedder=None, shield=None,
                 chunk_size: int = 1000, chunk_overlap: int = 200,
                 image_describer=None):
        self.store = store or SqliteVectorStore()
        self.embedder = embedder or DeterministicEmbedder()
        self.shield = shield
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        # Optional callable(path) -> str for images / process diagrams (OCR or a
        # vision model). Without it, image uploads are skipped (not read as bytes).
        self.image_describer = image_describer

    def close(self) -> None:
        """Release the backing store's resources (e.g. the SQLite connection).

        No-op for stores that don't expose ``close`` (e.g. a future pgvector
        pool managed elsewhere)."""
        closer = getattr(self.store, "close", None)
        if callable(closer):
            closer()

    def __enter__(self) -> KnowledgeBase:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _safe(self, text: str) -> bool:
        """Screen a chunk on the way in. The built-in injection-marker tripwire
        ALWAYS runs (even with no Shield wired, the common default), so a poisoned
        document can't ride into prompts via search_formatted. A configured Shield
        runs in addition. Fail-open ONLY on a Shield scanner error, mirroring the
        kernel's shield contract -- the marker screen itself never errors."""
        if _INJECTION_RE.search(_screen_text(text)):
            log.warning("knowledge: dropping chunk with injection marker on ingest")
            return False
        if self.shield is None:
            return True
        step = _SHIELD_WINDOW - _SHIELD_WINDOW_OVERLAP
        for start in range(0, max(1, len(text) - _SHIELD_WINDOW_OVERLAP), step):
            try:
                # An ingested chunk is untrusted CONTENT (like tool output), so
                # use the indirect-injection / content detector, not the
                # prompt-tuned scan_input.
                verdict = self.shield.scan_output(text[start:start + _SHIELD_WINDOW])
            except Exception as e:
                # Fail open (kernel rule 1), but leave a trace.
                log.warning("knowledge: shield scan failed on ingest (%s); allowing", e)
                continue
            if getattr(verdict, "scan_error", False):
                log.warning("knowledge: shield reported a scan error on ingest; allowing")
            if not getattr(verdict, "allowed", True):
                return False
        return True

    def _source_replacement_snapshot(self, collection: str, source: str, metadata: dict) -> list:
        if not source or metadata["source"] != source:
            raise ValueError("knowledge source replacement requires an unmodified source")
        reader = getattr(self.store, "read_where", None)
        if not callable(reader):
            raise RuntimeError("knowledge store cannot snapshot a source for replacement")
        with operation_scope(
            category="retrieval",
            service=f"vector-store:{type(self.store).__name__}",
            operation="knowledge-source-replacement-read",
        ):
            snapshot = list(reader(collection, "source", source, limit=MAX_DOCUMENT_CHUNKS))
        if len(snapshot) > MAX_DOCUMENT_CHUNKS:
            raise ValueError("knowledge prior source exceeds its replacement boundary")
        return snapshot

    def ingest_text(self, collection: str, text: str, source: str = "", *,
                    subject: str = "", trust_tier: int = 2,
                    sensitivity: str = "internal", ingested_by: str = "",
                    extra_meta: dict | None = None, replace_source: bool = False,
                    effect_guard=None, publication_scope=None) -> int:
        """Chunk, shield-scan, embed and store one document's text. Returns the
        number of chunks stored (poisoned chunks are dropped).

        Every chunk is stamped with provenance so retrieval and governance can
        reason about where a passage came from and whose data it is:

        * ``source``     — document path/URL (the citation).
        * ``subject``    — the data-subject key (e.g. ``slack:U123``) this
          document belongs to, so a GDPR erasure can find and remove it; empty
          for reference material with no subject.
        * ``trust_tier`` — 3 first-party … 0 external/untrusted (the same
          provenance scale memory-guard uses).
        * ``sensitivity``— data-classification label (public/internal/…).
        * ``ingested_by``— the principal that loaded it (audit attribution).
        * ``doc_sha256`` — content hash (dedup + tamper-evidence).

        At most 2,048 chunks are admitted, matching the default exact-document
        projection. ``replace_source`` stages a revision before atomically
        replacing this source's prior rows; a concurrent source change refuses
        the replacement. Matching retries retain the admitted rows unchanged.
        """
        document_text = str(text or "")
        if effect_guard is not None:
            effect_guard()
        if not document_text.strip():
            return 0
        size = max(1, int(self.chunk_size))
        overlap = max(0, min(int(self.chunk_overlap), size - 1))
        step = size - overlap
        if (len(document_text) + step - 1) // step > MAX_DOCUMENT_CHUNKS:
            raise ValueError(f"knowledge document exceeds {MAX_DOCUMENT_CHUNKS} chunks")
        descriptor, fingerprint = identity(self.embedder)
        self._require_embedding_identity(collection, fingerprint)
        raw_chunks = [
            (start, min(start + size, len(document_text)), document_text[start:start + size])
            for start in range(0, len(document_text), step)
        ]
        chunks = [chunk for _start, _end, chunk in raw_chunks]
        # Boundary-split evasion guard: an attacker can straddle an injection
        # tripwire across a chunk edge (or pick a small chunk_size) so no single
        # chunk matches the marker even though the full document does. Screen the
        # FULL text unconditionally -- the old `len(chunks) == len(raw_chunks)`
        # guard skipped this whenever any one chunk was also independently
        # dropped, letting a straddled payload's remaining chunks through.
        if not self._safe(document_text):
            log.warning("knowledge: dropping document with boundary-split "
                        "injection marker on ingest")
            return 0
        # Exact projection cannot reconstruct a document with a screened-out
        # middle range. Drop the whole document rather than storing a partial
        # source whose digest and offsets could never validate.
        if not chunks or any(not self._safe(chunk) for chunk in chunks):
            return 0
        document_sha256 = hashlib.sha256(document_text.encode("utf-8")).hexdigest()
        base_meta = {
            "source": source,
            "subject": subject,
            "trust_tier": int(trust_tier),
            "sensitivity": sensitivity,
            "ingested_by": ingested_by,
        }
        if extra_meta:
            base_meta.update(extra_meta)
        base_meta.pop("ingested_at", None)
        # Exact-layout keys are reserved. They bind every row to one complete
        # immutable document and may not be replaced through extra metadata.
        base_meta.update(
            document_schema=_EXACT_DOCUMENT_SCHEMA,
            document_length=len(document_text),
            doc_sha256=document_sha256,
            chunk_count=len(chunks),
            embedding_identity=descriptor,
            embedding_fingerprint=fingerprint,
        )
        exact_reader = getattr(self.store, "read_where", None)
        source_snapshot = (
            self._source_replacement_snapshot(collection, source, base_meta)
            if replace_source else None
        )
        try:
            existing = (
                self.exact_document(collection, document_sha256)
                if callable(exact_reader)
                else None
            )
        except LookupError:
            existing = None
        except RuntimeError as reconstruction_error:
            # An interrupted deterministic upsert is repairable, but the rows
            # that survived already bind this digest to their provenance.  Do
            # not let a retry silently replace that provenance merely because
            # the incomplete set cannot yet pass exact reconstruction.
            with operation_scope(
                category="retrieval",
                service=f"vector-store:{type(self.store).__name__}",
                operation="knowledge-interrupted-document-read",
            ):
                surviving = list(
                    exact_reader(
                        collection,
                        "doc_sha256",
                        document_sha256,
                        limit=MAX_DOCUMENT_CHUNKS,
                    )
                )
            for row in surviving:
                surviving_meta = {
                    key: value
                    for key, value in row.meta.items()
                    if key not in _EXACT_CHUNK_KEYS and key != "ingested_at"
                }
                if surviving_meta != base_meta:
                    raise RuntimeError(
                        "knowledge document digest is already bound to different provenance"
                    ) from reconstruction_error
            existing = None
        if existing is not None:
            existing_meta = dict(existing["metadata"])
            existing_meta.pop("ingested_at", None)
            if existing["text"] != document_text or existing_meta != base_meta:
                raise RuntimeError(
                    "knowledge document digest is already bound to different provenance"
                )
            if not replace_source or all(
                row.meta.get("doc_sha256") == document_sha256 for row in source_snapshot
            ):
                return int(existing["chunk_count"])
        publication_method = "replace_source_with_identity" if replace_source else "add_with_identity"
        guarded_add = getattr(self.store, publication_method, None)
        if not callable(guarded_add):
            raise RuntimeError(
                "knowledge store cannot atomically publish document provenance; "
                "use SQLite or pgvector for ingestion"
            )
        with operation_scope(
            category="storage",
            service=f"embedder:{type(self.embedder).__name__}",
            operation="knowledge-document-embedding",
        ):
            vectors = self.embedder.embed(chunks)
        validate_batch(vectors, len(chunks), descriptor["dimension"])
        if identity(self.embedder)[1] != fingerprint:
            raise RuntimeError("knowledge embedder changed during ingestion; retry")
        self._require_embedding_identity(collection, fingerprint)
        base_meta["ingested_at"] = time.time()
        items = [
            (
                hashlib.sha256(
                    (
                        "lightwork:vector-document-chunk:v1\0"
                        f"{collection}\0{document_sha256}\0{index}"
                    ).encode()
                ).hexdigest(),
                c,
                v,
                {
                    **base_meta,
                    "chunk_index": index,
                    "chunk_start": start,
                    "chunk_end": end,
                },
            )
            for index, ((start, end, c), v) in enumerate(
                zip(raw_chunks, vectors, strict=True)
            )
        ]
        with operation_scope(
            category="storage",
            service=f"vector-store:{type(self.store).__name__}",
            operation="knowledge-document-storage",
        ):
            publication_guards = _publication_guards(effect_guard, publication_scope)
            if replace_source:
                guarded_add(collection, items, fingerprint, source=source, snapshot=source_snapshot, **publication_guards)
            else:
                guarded_add(collection, items, fingerprint, **publication_guards)
        self._require_embedding_identity(collection, fingerprint)
        if callable(exact_reader):
            stored = self.exact_document(collection, document_sha256)
            # A concurrent matching admission or partial repair retains the
            # first admitted timestamp. It must match every immutable field.
            stored_meta = {key: value for key, value in stored["metadata"].items() if key != "ingested_at"}
            expected_meta = {key: value for key, value in base_meta.items() if key != "ingested_at"}
            if stored["text"] != document_text or stored_meta != expected_meta:
                raise RuntimeError("knowledge document storage verification failed")
            return int(stored["chunk_count"])
        return len(items)

    def exact_document(
        self,
        collection: str,
        doc_sha256: str,
        *,
        max_chunks: int = MAX_DOCUMENT_CHUNKS,
    ) -> dict:
        """Read one complete ingested document by its immutable digest.

        Only documents ingested with explicit chunk positions are eligible.
        Duplicate or partial copies fail closed because neither similarity
        ranking nor database row order can prove the original document order.
        """
        if (
            not isinstance(doc_sha256, str)
            or len(doc_sha256) != 64
            or any(char not in "0123456789abcdef" for char in doc_sha256)
        ):
            raise ValueError("knowledge document digest must be lowercase SHA-256")
        if not isinstance(max_chunks, int) or isinstance(max_chunks, bool) or max_chunks < 1:
            raise ValueError("knowledge exact document chunk limit must be positive")
        reader = getattr(self.store, "read_where", None)
        if not callable(reader):
            raise RuntimeError("knowledge store cannot perform exact document reads")
        with operation_scope(
            category="retrieval",
            service=f"vector-store:{type(self.store).__name__}",
            operation="knowledge-exact-document-read",
        ):
            rows = list(
                reader(
                    collection,
                    "doc_sha256",
                    doc_sha256,
                    limit=max_chunks,
                )
            )
        if not rows:
            raise LookupError("knowledge document was not found")
        if len(rows) > max_chunks:
            raise RuntimeError("knowledge document exceeds its exact projection boundary")
        first = rows[0].meta
        count = first.get("chunk_count")
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count != len(rows)
            or count < 1
        ):
            raise RuntimeError("knowledge document ordering commitment is incomplete")
        if first.get("document_schema") != _EXACT_DOCUMENT_SCHEMA:
            raise RuntimeError("knowledge document exact-layout commitment is unavailable")
        document_length = first.get("document_length")
        if (
            not isinstance(document_length, int)
            or isinstance(document_length, bool)
            or document_length < 1
        ):
            raise RuntimeError("knowledge document exact-layout commitment is malformed")
        positions: dict[int, tuple[int, int, str]] = {}
        stable = {
            key: value for key, value in first.items() if key not in _EXACT_CHUNK_KEYS
        }
        for row in rows:
            meta = row.meta
            index = meta.get("chunk_index")
            start = meta.get("chunk_start")
            end = meta.get("chunk_end")
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 0 <= index < count
                or index in positions
                or not isinstance(start, int)
                or isinstance(start, bool)
                or not isinstance(end, int)
                or isinstance(end, bool)
                or not 0 <= start < end <= document_length
                or len(row.text) != end - start
                or {
                    key: value
                    for key, value in meta.items()
                    if key not in _EXACT_CHUNK_KEYS
                } != stable
            ):
                raise RuntimeError("knowledge document ordering commitment is ambiguous")
            positions[index] = (start, end, row.text)
        if set(positions) != set(range(count)):
            raise RuntimeError("knowledge document ordering commitment is incomplete")
        reconstructed = ""
        covered = 0
        for index in range(count):
            start, end, chunk = positions[index]
            if start > covered:
                raise RuntimeError("knowledge document ordering commitment is incomplete")
            overlap_end = min(end, covered)
            if overlap_end > start and reconstructed[start:overlap_end] != chunk[:overlap_end - start]:
                raise RuntimeError("knowledge document overlapping chunks conflict")
            if end > covered:
                reconstructed += chunk[covered - start:]
                covered = end
        if covered != document_length or len(reconstructed) != document_length:
            raise RuntimeError("knowledge document ordering commitment is incomplete")
        actual_sha256 = hashlib.sha256(reconstructed.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(actual_sha256, doc_sha256):
            raise RuntimeError("knowledge document content does not match its declared digest")
        return {
            "schema": "lightwork.vector-knowledge-document.v1",
            "collection": str(collection),
            "doc_sha256": doc_sha256,
            "source": str(stable["source"] or ""),
            "subject": str(stable["subject"] or ""),
            "trust_tier": stable["trust_tier"],
            "sensitivity": str(stable["sensitivity"] or ""),
            "ingested_by": str(stable["ingested_by"] or ""),
            "ingested_at": stable["ingested_at"],
            "document_schema": _EXACT_DOCUMENT_SCHEMA,
            "document_length": document_length,
            "chunk_count": count,
            "metadata": stable,
            "text": reconstructed,
            "chunks": [
                {
                    "index": index,
                    "start": positions[index][0],
                    "end": positions[index][1],
                    "text": positions[index][2],
                    "sha256": hashlib.sha256(
                        positions[index][2].encode("utf-8")
                    ).hexdigest(),
                }
                for index in range(count)
            ],
        }

    def ingest_path(self, collection: str, path, *, subject: str = "",
                    trust_tier: int = 2, sensitivity: str = "internal",
                    ingested_by: str = "") -> int:
        """Ingest a document from disk (parsed by extension).

        Images / process diagrams go through ``image_describer`` (OCR or a
        vision model); without one they're skipped rather than read as bytes.
        The resulting text is shield-scanned like any other document, and every
        chunk carries the provenance passed here (subject / trust_tier /
        sensitivity / ingested_by)."""
        from .parse import is_image
        extraction_meta = None
        if is_image(path):
            if self.image_describer is None:
                log.info("knowledge: skipping image %s (no image_describer set)", path)
                return 0
            try:
                with operation_scope(
                    category="generation",
                    service="knowledge-image-describer",
                    operation="knowledge-image-description",
                ):
                    text = self.image_describer(str(path))
            except Exception as e:  # a describer failure must not abort ingestion
                log.warning("knowledge: image describer failed on %s: %s", path, e)
                return 0
        else:
            extraction = extract_document(path)
            if extraction.status in {"unsupported", "unavailable", "failed"}:
                raise RuntimeError("; ".join(extraction.warnings))
            if extraction.status == "rejected":
                raise ValueError("; ".join(extraction.warnings))
            text = extraction.text
            extraction_meta = {"extraction": extraction.metadata()}
        return self.ingest_text(
            collection, text, source=str(path), subject=subject,
            trust_tier=trust_tier, sensitivity=sensitivity, ingested_by=ingested_by,
            extra_meta=extraction_meta)

    # --- governance: erasure + verification over provenance -------------------

    def collections(self) -> list[str]:
        """Every collection the backing store holds (the erasure sweep surface).
        Unavailable enumeration cannot establish that a store is empty."""
        fn = getattr(self.store, "collections", None)
        if not callable(fn):
            raise RuntimeError("knowledge store cannot enumerate collections")
        with operation_scope(
            category="retrieval",
            service=f"vector-store:{type(self.store).__name__}",
            operation="knowledge-collection-list",
        ):
            return list(fn())

    def erase_subject(self, subject: str, collections=None) -> dict[str, int]:
        """Delete every chunk belonging to ``subject`` (GDPR Art. 17).

        Sweeps the given collections (or every collection when ``None``) and
        removes chunks whose provenance ``subject`` matches. Returns
        ``{collection: chunks_removed}`` for the non-empty deletions — the
        evidence a caller records to the signed audit chain.
        """
        if not subject:
            return {}
        cols = list(collections) if collections is not None else self.collections()
        out: dict[str, int] = {}
        for c in cols:
            with operation_scope(
                category="update",
                service=f"vector-store:{type(self.store).__name__}",
                operation="knowledge-subject-erasure",
            ):
                n = self.store.delete_where(c, "subject", subject)
            if n:
                out[c] = n
        return out

    def erase_source(self, source: str, collections=None) -> dict[str, int]:
        """Delete every chunk from one document ``source`` (retract a document).
        Same shape as :meth:`erase_subject`."""
        if not source:
            return {}
        cols = list(collections) if collections is not None else self.collections()
        out: dict[str, int] = {}
        for c in cols:
            with operation_scope(
                category="update",
                service=f"vector-store:{type(self.store).__name__}",
                operation="knowledge-source-erasure",
            ):
                n = self.store.delete_where(c, "source", source)
            if n:
                out[c] = n
        return out

    def count_subject(self, subject: str, collections=None) -> int:
        """Residual chunks for ``subject`` — the erasure-verify primitive
        (should be 0 after :meth:`erase_subject`)."""
        if not subject:
            return 0
        cols = list(collections) if collections is not None else self.collections()
        total = 0
        for collection in cols:
            with operation_scope(
                category="retrieval",
                service=f"vector-store:{type(self.store).__name__}",
                operation="knowledge-subject-count",
            ):
                total += self.store.count_where(collection, "subject", subject)
        return total

    def delete_collection(self, collection: str) -> None:
        """Delete an unapproved or retired collection from the backing store."""
        with operation_scope(
            category="update",
            service=f"vector-store:{type(self.store).__name__}",
            operation="knowledge-collection-delete",
        ):
            self.store.delete_collection(collection)

    def _require_embedding_identity(self, collection: str, fingerprint: str) -> None:
        total = self.store.count(collection)
        matching = self.store.count_where(collection, FINGERPRINT_KEY, fingerprint)
        if total != matching:
            raise RuntimeError(
                f"knowledge collection {collection!r} requires explicit reindex: "
                "stored embedding identity differs or is unknown"
            )

    def reindex(self, collection: str, *, max_chunks: int = 100_000) -> int:
        """Replace vectors atomically without changing content, provenance or IDs.

        Only stores providing compare-and-replace support can migrate in place.
        Other backends must migrate originals into a new SQLite or pgvector
        collection and switch the configured source after validating it.
        """
        reader = getattr(self.store, "read_collection", None)
        replace = getattr(self.store, "replace_embeddings", None)
        if not callable(reader) or not callable(replace):
            raise RuntimeError("in-place reindex is unsupported for this backend; "
                               "ingest originals into a new collection in SQLite or pgvector and switch sources")
        rows = reader(collection, limit=max_chunks)
        if len(rows) > max_chunks:
            raise RuntimeError("knowledge reindex exceeds its chunk limit")
        descriptor, fingerprint = identity(self.embedder)
        items = []
        for start in range(0, len(rows), 64):
            batch = rows[start:start + 64]
            with operation_scope(category="storage", service=f"embedder:{type(self.embedder).__name__}",
                                 operation="knowledge-reindex-embedding"):
                vectors = self.embedder.embed([row.text for row in batch])
            validate_batch(vectors, len(batch), descriptor["dimension"])
            items.extend((row.chunk_id, row.text, vector,
                          {**row.meta, IDENTITY_KEY: descriptor, FINGERPRINT_KEY: fingerprint})
                         for row, vector in zip(batch, vectors, strict=True))
        if identity(self.embedder)[1] != fingerprint:
            raise RuntimeError("knowledge embedder changed during reindex; retry")
        replace(collection, rows, items)
        self._require_embedding_identity(collection, fingerprint)
        return len(items)

    def _search_vec(self, collection: str, vector, k: int, fingerprint: str) -> list[Hit]:
        """Store lookup for an already-embedded query; one Hit-wrap site."""
        self._require_embedding_identity(collection, fingerprint)
        with operation_scope(
            category="retrieval",
            service=f"vector-store:{type(self.store).__name__}",
            operation="knowledge-vector-search",
        ):
            matches = self.store.search(collection, vector, k)
        self._require_embedding_identity(collection, fingerprint)
        if any(m.meta.get(FINGERPRINT_KEY) != fingerprint for m in matches):
            raise RuntimeError("knowledge embedding identity changed during search; retry")
        return [Hit(m.score, m.text, m.meta.get("source", "")) for m in matches]

    def search(self, collection: str, query: str, k: int = 5) -> list[Hit]:
        descriptor, fingerprint = identity(self.embedder)
        self._require_embedding_identity(collection, fingerprint)
        with operation_scope(
            category="retrieval",
            service=f"embedder:{type(self.embedder).__name__}",
            operation="knowledge-query-embedding",
        ):
            vector = getattr(self.embedder, "embed_query", self.embedder.embed)([query])[0]
        validate_batch([vector], 1, descriptor["dimension"])
        if identity(self.embedder)[1] != fingerprint:
            raise RuntimeError("knowledge embedder changed during search; retry")
        return self._search_vec(collection, vector, k, fingerprint)

    def search_formatted(self, collections, query: str, k: int = 5) -> str:
        """Search one or more domain collections and render the top-k chunks with
        their sources. (The kernel's ``knowledge_search`` tool does not call
        this; it goes through ``KnowledgeAccessService``.) Merges across
        collections, then keeps the globally top-k.

        The query is embedded once and the vector reused per collection, and
        redundant chunk content (the chunker's overlap, contained duplicates)
        is collapsed before the k-slice -- absorbed duplicates make room for
        the next-best distinct chunk rather than shrinking the result, and the
        model never pays tokens for the same span twice."""
        descriptor, fingerprint = identity(self.embedder)
        collections = tuple(collections)
        for collection in collections:
            self._require_embedding_identity(collection, fingerprint)
        with operation_scope(
            category="retrieval",
            service=f"embedder:{type(self.embedder).__name__}",
            operation="knowledge-query-embedding",
        ):
            vector = getattr(self.embedder, "embed_query", self.embedder.embed)([query])[0]
        validate_batch([vector], 1, descriptor["dimension"])
        if identity(self.embedder)[1] != fingerprint:
            raise RuntimeError("knowledge embedder changed during search; retry")
        hits: list[Hit] = []
        for c in collections:
            hits.extend(self._search_vec(c, vector, k, fingerprint))
        hits.sort(key=lambda h: h.score, reverse=True)
        hits = _dedup_hits(hits, max_overlap=self.chunk_overlap)[: max(1, k)]
        if not hits:
            return "No relevant documents found in this domain's knowledge base."
        return "\n\n".join(
            f"[source: {_source_label(h.source)}]\n{h.text}" for h in hits
        )
