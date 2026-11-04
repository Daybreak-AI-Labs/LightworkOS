"""Governed adapter rung -- in-tenant weights adaptation on the promotion ladder.

The promotion ladder (``maverick.self_improvement``) has always declared a
``weights`` rung -- min 20 samples, capability evidence, human signature -- and
``Candidate.payload`` was designed to carry "a trained adapter ref". This module
supplies the plumbing between a trained LoRA adapter directory and that rung, so
a tenant's own model adaptation runs under the same governance chain as code
self-modification:

* **provenance boundary** -- training examples carry a provenance tag; frontier
  model output is refused by default (the distillation-ToS guard), synthetic
  data is refused by default, unknown provenance is always refused. The kept
  dataset is content-hashed so the manifest pins WHAT the adapter learned from.
* **payload hygiene** -- an adapter directory may contain only inert weight/
  metadata files (safetensors/gguf/json/text). Code and pickle-bearing formats
  (``.py``, ``.pt``, ``.bin``, ...) are refused structurally, BEFORE any eval
  runs -- a "weights" payload can therefore never smuggle executable authority.
* **held-out fitness + overfit refusal** -- baseline vs candidate scored on a
  deterministic held-in/held-out split (same rule as the code rung): a gain on
  seen cases with no gain on unseen cases is OVERFIT and refused.
* **signed promotion, append-only ledger, one-step rollback** -- the existing
  ``SelfImprovementController`` / ``PromotionLedger`` / ``approval_signing``
  chain, at rung ``weights``; activation archives the previous pointer and
  ``AdapterStore.rollback()`` restores it byte-identically.

The two expensive seams are pluggable and disclosed, mirroring how the code
rung stubs its LLM proposer: the ``stub`` trainer writes a deterministic
artifact (no GPU, no deps) for proofs/tests, while ``dpo-lora`` delegates to
the real QLoRA/DPO trainer in ``maverick.training.rlaif`` (``[training]``
extra). Serving attaches a PROMOTED adapter via an Ollama Modelfile
``ADAPTER`` directive (:func:`render_modelfile`); the tuned model is resolved
by the Ollama provider client at request-build time
(:func:`effective_wire_model`), so spec parsing, admin allow-lists, pricing,
and telemetry all keep the stable base model id. No base model is ever
hard-coded -- the base comes from ``[adapter_rung] base_model`` in config.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import unicodedata
import uuid
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

log = logging.getLogger(__name__)

# --- provenance boundary ---------------------------------------------------------

# Where a training example came from. ``model_output`` (a frontier model's own
# completion) is refused by default: training a tenant adapter on it is the
# contested distillation lane and most provider ToS restrict it. The defensible
# default is the tenant's OWN signal: human corrections/examples and traces of
# the tenant's real runs.
PROVENANCE_KINDS: tuple[str, ...] = (
    "human_correction", "human_example", "tenant_trace", "synthetic", "model_output")


@dataclass(frozen=True)
class TrainExample:
    """One preference pair (or plain completion when ``rejected`` is empty)."""

    prompt: str
    chosen: str
    rejected: str = ""
    provenance: str = "tenant_trace"
    source_id: str = ""


@dataclass(frozen=True)
class DatasetReview:
    """Outcome of screening a training set at the provenance boundary."""

    ok: bool
    kept: tuple[TrainExample, ...]
    refused: tuple[str, ...]          # human-readable refusal reasons, one per drop
    dataset_sha256: str = ""          # digest of the KEPT set (what training may see)
    provenance_counts: dict = field(default_factory=dict)


def screen_examples(
    examples: list[TrainExample] | tuple[TrainExample, ...],
    *,
    allow_synthetic: bool = False,
    allow_model_output: bool = False,
) -> DatasetReview:
    """Apply the provenance boundary. Unknown provenance is ALWAYS refused
    (fail-closed); ``synthetic`` and ``model_output`` are refused unless the
    operator opted in via config. An empty kept-set is not ok -- an adapter
    trained on nothing is meaningless and must not reach the ladder."""
    kept: list[TrainExample] = []
    refused: list[str] = []
    counts: dict[str, int] = {}
    for i, ex in enumerate(examples):
        prov = (ex.provenance or "").strip()
        if prov not in PROVENANCE_KINDS:
            refused.append(f"example {i} ({ex.source_id or 'unlabelled'}): "
                           f"unknown provenance {prov!r}")
            continue
        if prov == "model_output" and not allow_model_output:
            refused.append(f"example {i} ({ex.source_id or 'unlabelled'}): model_output "
                           "provenance refused (distillation guard; "
                           "[adapter_rung] allow_model_output)")
            continue
        if prov == "synthetic" and not allow_synthetic:
            refused.append(f"example {i} ({ex.source_id or 'unlabelled'}): synthetic "
                           "provenance refused ([adapter_rung] allow_synthetic)")
            continue
        counts[prov] = counts.get(prov, 0) + 1
        kept.append(ex)
    digest = _dataset_digest(kept) if kept else ""
    return DatasetReview(ok=bool(kept), kept=tuple(kept), refused=tuple(refused),
                         dataset_sha256=digest, provenance_counts=counts)


def _dataset_digest(examples: list[TrainExample]) -> str:
    """Order-independent content hash of a kept training set."""
    h = hashlib.sha256()
    for line in sorted(
        json.dumps([ex.prompt, ex.chosen, ex.rejected, ex.provenance],
                   ensure_ascii=False)
        for ex in examples
    ):
        h.update(line.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


# --- payload hygiene -------------------------------------------------------------

# The actual learned weights an adapter must contain (inert-by-format). At least
# one of these must be present or the payload is not an adapter at all.
WEIGHT_SUFFIXES: frozenset[str] = frozenset({".safetensors", ".gguf"})

# Fail-closed allowlist: everything else -- notably code (.py/.sh), native
# binaries (.so/.dll) and pickle-bearing torch formats (.pt/.pth/.bin/.pkl) --
# is refused. safetensors/gguf are inert weights; json/txt/md/model carry inert
# metadata (config, tokenizer protobuf, model card) that real HF/PEFT exports
# ship. ``.model`` is a sentencepiece protobuf (data, not executable).
ALLOWED_ADAPTER_SUFFIXES: frozenset[str] = frozenset(
    {".safetensors", ".gguf", ".json", ".txt", ".md", ".model"})

# Extensionless metadata files a standard adapter export carries. Kept as an
# explicit, narrow set so an arbitrary extensionless file (which could be a
# script) is still refused -- only these exact inert basenames pass.
ALLOWED_ADAPTER_BASENAMES: frozenset[str] = frozenset({".gitattributes", "LICENSE"})

MANIFEST_BASENAME = "manifest.json"
SERVING_BASENAME = "Modelfile.txt"  # generated at promotion; not part of the weights

# Adapters are legitimately large, but an untrusted training output must not
# make review allocate one giant file or walk/hash an unbounded tree.  These
# ceilings accommodate heavily sharded multi-GB LoRAs while keeping the
# privileged promotion path's CPU, memory, and disk exposure finite.
MAX_ADAPTER_ENTRIES = 4096
MAX_ADAPTER_FILES = 1024
MAX_ADAPTER_FILE_BYTES = 8 * 1024**3
MAX_ADAPTER_TOTAL_BYTES = 32 * 1024**3
ADAPTER_IO_CHUNK_BYTES = 4 * 1024**2
OLLAMA_INSTALL_TIMEOUT_SECONDS = 60 * 60
OLLAMA_API_TIMEOUT_SECONDS = 15
OLLAMA_API_RESPONSE_BYTES = 8 * 1024**2
# Ollama aliases are mutable.  A positive cache window would route a poisoned
# replacement until expiry, so production resolution re-attests every request.
# File hashing remains metadata-cached; only the small local inventory query is
# repeated.  A future explicitly non-production profile may opt into staleness.
SERVING_ALIAS_REVERIFY_SECONDS = 0.0
MAX_APPROVAL_PAYLOAD_BYTES = 128 * 1024
ADAPTER_AUTHORITY_PAYLOAD_VERSION = 1
MODEL_IMPROVEMENT_BINDING_SCHEMA = (
    "lightwork.adapter-model-improvement-binding.v1"
)


def _is_allowed_payload_file(name: str, suffix: str) -> bool:
    return suffix.lower() in ALLOWED_ADAPTER_SUFFIXES or name in ALLOWED_ADAPTER_BASENAMES


def _is_unsafe_link(path: Path) -> bool:
    """True for a POSIX symlink or Windows reparse-point/junction.

    ``Path.is_symlink`` is not sufficient on Windows: directory junctions are
    independently traversable reparse points and can redirect a reviewed tree
    outside the tenant's artifact root.
    """
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attrs = getattr(os.lstat(path), "st_file_attributes", 0)
        marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return bool(attrs & marker)
    except OSError:
        return False


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    """Metadata identity used to detect replacement or in-place mutation."""
    return (
        int(value.st_dev), int(value.st_ino), int(value.st_mode), int(value.st_size),
        int(getattr(value, "st_mtime_ns", int(value.st_mtime * 1_000_000_000))),
        int(getattr(value, "st_ctime_ns", int(value.st_ctime * 1_000_000_000))),
    )


def _open_file_identity(value: os.stat_result) -> tuple[int, ...]:
    """Stable identity across Windows path-stat and handle-stat APIs.

    Windows may lazily reconcile creation/change time when a fresh file is
    first opened, so ctime is useful for cache invalidation but cannot safely
    participate in the pre-open TOCTOU comparison.
    """
    return _stat_identity(value)[:5]


def _bounded_payload_files(
    root: Path,
) -> list[tuple[Path, Path, os.stat_result]]:
    """Enumerate regular files without ever materialising an unbounded tree."""
    if _is_unsafe_link(root) or not root.is_dir():
        raise ValueError("adapter payload root is missing or unsafe")
    resolved_root = root.resolve()
    entries = 0
    total = 0
    files: list[tuple[Path, Path, os.stat_result]] = []
    try:
        for path in root.rglob("*"):
            entries += 1
            if entries > MAX_ADAPTER_ENTRIES:
                raise ValueError(
                    f"adapter payload exceeds {MAX_ADAPTER_ENTRIES} filesystem entries")
            if _is_unsafe_link(path):
                raise ValueError(
                    f"adapter payload contains a symlink/reparse point: {path}")
            if not path.resolve().is_relative_to(resolved_root):
                raise ValueError(f"adapter payload escapes its root: {path}")
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError(f"adapter payload contains a non-regular file: {path}")
            if len(files) >= MAX_ADAPTER_FILES:
                raise ValueError(f"adapter payload exceeds {MAX_ADAPTER_FILES} files")
            if info.st_size > MAX_ADAPTER_FILE_BYTES:
                raise ValueError(
                    f"adapter payload file exceeds {MAX_ADAPTER_FILE_BYTES} bytes: {path}")
            total += info.st_size
            if total > MAX_ADAPTER_TOTAL_BYTES:
                raise ValueError(
                    f"adapter payload exceeds {MAX_ADAPTER_TOTAL_BYTES} total bytes")
            files.append((path.relative_to(root), path, info))
    except OSError as exc:
        raise ValueError("adapter payload could not be safely enumerated") from exc
    files.sort(key=lambda item: str(item[0]))
    return files


def _stream_payload_file(
    path: Path, expected: os.stat_result, consume: Callable[[bytes], Any],
) -> int:
    """Stream one stable regular file into ``consume`` under the size ceiling."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"adapter payload file could not be opened safely: {path}") from exc
    total = 0
    try:
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            opened = os.fstat(source.fileno())
            if (not stat.S_ISREG(opened.st_mode)
                    or _open_file_identity(opened) != _open_file_identity(expected)):
                raise ValueError(f"adapter payload changed before read: {path}")
            while True:
                chunk = source.read(ADAPTER_IO_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ADAPTER_FILE_BYTES or total > expected.st_size:
                    raise ValueError(f"adapter payload grew during read: {path}")
                consume(chunk)
            closed = os.fstat(source.fileno())
        current = path.lstat()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (total != expected.st_size
            or _open_file_identity(closed) != _open_file_identity(expected)
            or _open_file_identity(current) != _open_file_identity(expected)):
        raise ValueError(f"adapter payload changed during read: {path}")
    return total


def _copy_payload_file(
    source: Path, destination: Path, expected: os.stat_result,
) -> None:
    """Bounded streaming copy into an unpublished, private staging tree."""
    from .file_lock import ensure_private_directory, harden_path_permissions
    ensure_private_directory(destination.parent)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_BINARY", 0))
    descriptor = os.open(destination, flags, 0o400)
    try:
        with os.fdopen(descriptor, "wb") as target:
            descriptor = -1
            _stream_payload_file(source, expected, target.write)
            target.flush()
            os.fsync(target.fileno())
        harden_path_permissions(destination, 0o400)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@dataclass(frozen=True)
class PayloadReview:
    ok: bool
    reason: str
    files: tuple[str, ...] = ()
    refused: tuple[str, ...] = ()


def review_adapter_payload(adapter_dir: Path | str) -> PayloadReview:
    """Structural hygiene check on an adapter directory. Refuses any file whose
    suffix is off the allowlist -- BEFORE any evaluation runs, mirroring how the
    code rung's anti-cheat boundary fires before a test does."""
    root = Path(adapter_dir)
    if not root.is_dir():
        return PayloadReview(False, f"not a directory: {root}")
    if _is_unsafe_link(root):
        return PayloadReview(False, f"adapter payload root is a symlink/reparse point: {root}")
    try:
        bounded = _bounded_payload_files(root)
    except ValueError as exc:
        return PayloadReview(False, str(exc))
    files: list[str] = []
    refused: list[str] = []
    for relative, p, _info in bounded:
        rel = str(relative)
        if _is_allowed_payload_file(p.name, p.suffix):
            files.append(rel)
        else:
            refused.append(rel)
    if refused:
        return PayloadReview(False, "forbidden file type(s) in adapter payload: "
                             + ", ".join(refused), tuple(files), tuple(refused))
    if not files:
        return PayloadReview(False, "empty adapter payload", (), ())
    # A payload of metadata alone (config/tokenizer, no .safetensors/.gguf) is
    # not an adapter: hygiene would pass but payload_digest_dir excludes the
    # manifest/Modelfile, so a weightless dir would sign the digest of nothing
    # (a constant that collides across every empty payload). Require weights.
    if not any(Path(f).suffix.lower() in WEIGHT_SUFFIXES for f in files):
        return PayloadReview(
            False, "no weight file (.safetensors/.gguf) in adapter payload",
            tuple(files), ())
    return PayloadReview(True, "payload clean", tuple(files), ())


def payload_digest_dir(adapter_dir: Path | str) -> str:
    """Deterministic digest over the payload's relative paths + bytes, so the
    Ed25519 approval is bound to the EXACT weights that were evaluated."""
    root = Path(adapter_dir)
    h = hashlib.sha256()
    for relative, path, info in _bounded_payload_files(root):
        if path.name in (MANIFEST_BASENAME, SERVING_BASENAME):
            continue
        h.update(str(relative).encode("utf-8"))
        h.update(b"\0")
        _stream_payload_file(path, info, h.update)
        h.update(b"\0")
    return h.hexdigest()


# --- manifest --------------------------------------------------------------------

@dataclass
class AdapterManifest:
    """What an adapter IS: base, trainer, data provenance, payload digest."""

    adapter_id: str
    base_model: str                    # full spec, e.g. "ollama:<model-id>" (from config)
    trainer: str
    dataset_sha256: str
    examples: int
    provenance_counts: dict = field(default_factory=dict)
    payload_sha256: str = ""
    created_at: float = field(default_factory=time.time)
    notes: str = ""
    # Raw operator-facing tenant identity.  Empty is the legacy/single-tenant
    # namespace.  The manifest (and later the signed approval payload) binds
    # the weights to this tenant so copying a payload between tenant stores
    # cannot silently grant it serving authority.
    tenant_id: str = ""

    def to_dict(self) -> dict:
        # Derived from the single field declaration -- adding a field can never
        # silently drop it from a saved manifest (the failure mode of a
        # hand-maintained parallel dict).
        return asdict(self)

    def save(self, adapter_dir: Path | str) -> Path:
        _validate_manifest(self)
        path = Path(adapter_dir) / MANIFEST_BASENAME
        _atomic_write_json(path, self.to_dict())
        return path

    @classmethod
    def load(cls, adapter_dir: Path | str) -> AdapterManifest:
        raw = json.loads((Path(adapter_dir) / MANIFEST_BASENAME).read_text(encoding="utf-8"))
        known = {f.name for f in fields(cls)}
        manifest = cls(**{k: v for k, v in raw.items() if k in known})
        _validate_manifest(manifest)
        return manifest


def _validated_tenant_id(value: str | None) -> str:
    """Return a bounded tenant id that is safe for identity and path binding."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("adapter tenant_id must be a string")
    if value != value.strip() or len(value) > 256 or any(ord(ch) < 32 for ch in value):
        raise ValueError("adapter tenant_id must be a bounded printable string")
    value = unicodedata.normalize("NFC", value)
    if value:
        # data_dir owns tenant path encoding and its length/collision policy.
        # Calling it here validates the raw id without duplicating that policy.
        from .paths import data_dir
        data_dir(tenant=value)
    return value


_ADAPTER_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MODEL_SPEC_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,511}\Z")


def _validate_manifest(manifest: AdapterManifest) -> None:
    """Validate every value that reaches a pointer, model name, or Modelfile."""
    manifest.tenant_id = _validated_tenant_id(manifest.tenant_id)
    if not isinstance(manifest.adapter_id, str) or not _ADAPTER_ID_RE.fullmatch(
        manifest.adapter_id
    ):
        raise ValueError("adapter_id must be a bounded ASCII identifier")
    if not isinstance(manifest.base_model, str) or not _MODEL_SPEC_RE.fullmatch(
        manifest.base_model
    ):
        raise ValueError("base_model must be a bounded model specification")
    for label, digest in (
        ("dataset_sha256", manifest.dataset_sha256),
        ("payload_sha256", manifest.payload_sha256),
    ):
        if digest and (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            raise ValueError(f"{label} must be lowercase sha256 hexadecimal")


def _active_tenant_id() -> str:
    from .paths import current_tenant_id
    return _validated_tenant_id(current_tenant_id())


def _tenant_tag(tenant_id: str) -> str:
    """Non-identifying stable tag for model names and artifact identities."""
    return hashlib.sha256(_validated_tenant_id(tenant_id).encode("utf-8")).hexdigest()[:10]


def _require_manifest_tenant(manifest: AdapterManifest, tenant_id: str) -> None:
    actual = _validated_tenant_id(manifest.tenant_id)
    expected = _validated_tenant_id(tenant_id)
    if actual != expected:
        raise ValueError(
            f"adapter manifest tenant mismatch: expected {expected or 'shared'!r}, "
            f"got {actual or 'shared'!r}")


def _atomic_write_json(path: Path, payload: dict) -> None:
    """0600 atomic JSON write. Delegates to the shared file_lock helper (unique
    mkstemp temp name + os.replace), so concurrent same-process writes to one
    target cannot collide on a PID-keyed temp name."""
    from .file_lock import atomic_write_text
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(payload, indent=1, sort_keys=True), mode=0o600)


# --- trainers (the pluggable expensive seam) ---------------------------------------

class Trainer(Protocol):
    """The seam every trainer implements: turn a screened dataset into a saved
    adapter directory + manifest."""

    name: str

    def train(self, review: DatasetReview, base_model: str,
              out_dir: Path | str) -> AdapterManifest: ...


def _finalize_manifest(review: DatasetReview, base_model: str, trainer_name: str,
                       out: Path, *, notes: str = "") -> AdapterManifest:
    """Build + save the manifest for a freshly-trained adapter dir. Single
    source of truth so stub- and dpo-trained adapters carry identical manifest
    shapes."""
    manifest = AdapterManifest(
        adapter_id=uuid.uuid4().hex[:12], base_model=base_model,
        trainer=trainer_name, dataset_sha256=review.dataset_sha256,
        examples=len(review.kept), provenance_counts=dict(review.provenance_counts),
        payload_sha256=payload_digest_dir(out), notes=notes,
        tenant_id=_active_tenant_id())
    manifest.save(out)
    return manifest


class StubTrainer:
    """Deterministic no-GPU trainer for proofs and tests, DISCLOSED as such:
    the artifact is a placeholder derived from the dataset digest, not learned
    weights. Everything downstream (hygiene, eval, gate, ledger, rollback) is
    the real chain -- this stubs only the gradient step, exactly as the code
    rung's proofs stub the LLM proposer."""

    name = "stub"

    def train(self, review: DatasetReview, base_model: str,
              out_dir: Path | str) -> AdapterManifest:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        blob = hashlib.sha256(("stub:" + review.dataset_sha256).encode()).digest()
        (out / "adapter.safetensors").write_bytes(blob * 32)
        return _finalize_manifest(
            review, base_model, self.name, out,
            notes="stub trainer: deterministic placeholder artifact (proof/test path)")


class DpoLoraTrainer:
    """Real QLoRA/DPO training, delegated to ``maverick.training.rlaif`` (the
    existing trainer behind the ``[training]`` extra). Import is guarded so a
    box without peft/torch gets a plain actionable error, not a stack trace.

    NOTE ``base_model`` here is an HF model id or local path (what the trainer
    loads), which is NOT the same identifier as the Ollama *serving* tag: a
    provider prefix (``ollama:``/``local:``) is stripped, but the remaining id
    must resolve for ``transformers.from_pretrained`` -- configure
    ``[adapter_rung] base_model`` to a name valid for both, or a local path."""

    name = "dpo-lora"

    def train(self, review: DatasetReview, base_model: str,
              out_dir: Path | str) -> AdapterManifest:
        try:
            from .training import rlaif
        except Exception as e:  # pragma: no cover -- exercised only sans extra
            raise RuntimeError(
                "dpo-lora trainer needs the [training] extra "
                "(peft/bitsandbytes/accelerate): pip install 'maverick[training]'"
            ) from e
        # rlaif.train wants list[dict] preference rows keyed chosen_text /
        # rejected_text (+ weight), NOT tuples; each side is a full prompt+
        # response sequence for the DPO logp. DPO needs a rejected side, so a
        # plain completion (empty rejected) cannot form a pair.
        pairs = [
            {"chosen_text": f"{ex.prompt}\n{ex.chosen}",
             "rejected_text": f"{ex.prompt}\n{ex.rejected}", "weight": 1.0}
            for ex in review.kept if ex.rejected.strip()
        ]
        if not pairs:
            raise RuntimeError(
                "dpo-lora needs preference pairs (each example needs a non-empty "
                "'rejected'); the screened set had only plain completions")
        # Strip the serving-provider prefix: transformers.from_pretrained needs
        # an HF id / path, not 'ollama:<tag>' (the colon makes it an invalid
        # repo id). See the class note on the id mismatch.
        hf_base = _model_id(base_model)
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        rc = rlaif.train(pairs, hf_base, str(out), lora=True)
        if rc != 0:
            raise RuntimeError(f"rlaif LoRA training failed (exit {rc})")
        hygiene = review_adapter_payload(out)
        if not hygiene.ok:
            # Torch checkpoints (.bin/.pt) are pickle-bearing; the trainer must
            # emit safetensors. Refuse rather than promote an unreviewable blob.
            raise RuntimeError(f"trained payload failed hygiene: {hygiene.reason}")
        return _finalize_manifest(review, base_model, self.name, out)


_TRAINERS: dict[str, Callable[[], Trainer]] = {
    StubTrainer.name: StubTrainer,
    DpoLoraTrainer.name: DpoLoraTrainer,
}


def get_trainer(name: str) -> Trainer:
    """Trainer registry lookup; unknown names fail with the known options."""
    try:
        return _TRAINERS[name]()
    except KeyError:
        raise ValueError(
            f"unknown adapter trainer {name!r}; known: {sorted(_TRAINERS)}") from None


# --- held-out fitness --------------------------------------------------------------

@dataclass
class AdapterEvalResult:
    ok: bool = False
    baseline_score: float = 0.0        # held-OUT rates: what the gate judges
    candidate_score: float = 0.0
    held_in_baseline: float = 0.0
    held_in_candidate: float = 0.0
    samples: int = 0                   # held-out case count (one case = one trial)
    overfit: bool = False
    reason: str = ""


def evaluate_adapter(
    base_ref: str,
    candidate_ref: str,
    case_ids: list[str],
    *,
    score_fn: Callable[[str, list[str]], dict[str, bool]],
    held_out_frac: float = 0.35,
) -> AdapterEvalResult:
    """Score base vs base+adapter on a deterministic held-in/held-out split.

    ``score_fn(model_ref, case_ids) -> {case_id: passed}`` is the eval seam: in
    production it runs the tenant's private evals against the serving stack
    (base vs tuned model); proofs and tests stub it. The split reuses
    ``self_harness_eval.corpus_split`` (stable content-hash order) and the
    overfit rule is byte-for-byte the code rung's: better on seen, not better
    on unseen => memorisation, refused."""
    from .self_harness_eval import corpus_split

    out = AdapterEvalResult()
    ids = [str(c) for c in case_ids]
    held_in, held_out = corpus_split([{"goal": c} for c in ids],
                                     held_out_frac=held_out_frac)
    if not held_out:
        out.reason = "no held-out cases (need >= 2 eval cases)"
        return out
    base = score_fn(base_ref, ids)
    cand = score_fn(candidate_ref, ids)

    def _rate(resolved: dict[str, bool], subset: list[str]) -> float:
        return sum(1 for c in subset if resolved.get(c)) / len(subset) if subset else 0.0

    out.held_in_baseline, out.held_in_candidate = _rate(base, held_in), _rate(cand, held_in)
    out.baseline_score, out.candidate_score = _rate(base, held_out), _rate(cand, held_out)
    out.samples = len(held_out)
    out.overfit = (out.held_in_candidate > out.held_in_baseline
                   and out.candidate_score <= out.baseline_score)
    if out.overfit:
        out.reason = (f"OVERFIT: held-in {out.held_in_baseline:.3f}->"
                      f"{out.held_in_candidate:.3f} but held-out "
                      f"{out.baseline_score:.3f}->{out.candidate_score:.3f}")
        return out
    out.ok = True
    out.reason = (f"held-out {out.baseline_score:.3f} -> {out.candidate_score:.3f} "
                  f"over {out.samples} unseen cases")
    return out


# --- adapter store (activation pointer + one-step rollback) -------------------------

ACTIVE_BASENAME = "active.json"
PREVIOUS_BASENAME = "previous.json"
POINTER_STATE_BASENAME = "pointer-state.json"


@dataclass(frozen=True)
class _PointerState:
    active: dict | None = None
    previous: dict | None = None
    pending_rollback: dict | None = None


@dataclass(frozen=True)
class AdapterActivationPlan:
    """Exact before/after revisions for one tenant-scoped pointer CAS."""

    before: Any
    after: Any
    pointer: dict
    state: _PointerState = field(repr=False)


def _validated_approval_public_keys(
    value: list[str] | tuple[str, ...] | None,
) -> tuple[str, ...]:
    """Return a non-empty, canonical set of trusted Ed25519 public keys."""
    if value is None or isinstance(value, (str, bytes)):
        raise ValueError(
            "governed adapter promotion requires explicit trusted approval public keys")
    keys: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise ValueError("adapter approval public keys must be hexadecimal strings")
        key = raw.strip().lower()
        try:
            decoded = bytes.fromhex(key)
        except ValueError as exc:
            raise ValueError("adapter approval public key is not hexadecimal") from exc
        if len(decoded) != 32 or len(key) != 64:
            raise ValueError("adapter approval public key must be 32 bytes")
        if key not in keys:
            keys.append(key)
    if not keys:
        raise ValueError(
            "governed adapter promotion requires explicit trusted approval public keys")
    return tuple(keys)


def _validated_model_improvement_binding(  # noqa: C901
    value: object,
) -> dict[str, Any]:
    """Validate the content-free evidence bundle carried by a live pointer."""
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "policy_sha256",
        "training_receipt",
        "qualification",
    }:
        raise ValueError("adapter model-improvement binding has an invalid shape")
    if value.get("schema") != MODEL_IMPROVEMENT_BINDING_SCHEMA:
        raise ValueError("adapter model-improvement binding schema is unsupported")

    def digest(raw: object, field: str) -> str:
        if (
            not isinstance(raw, str)
            or len(raw) != 64
            or any(char not in "0123456789abcdef" for char in raw)
        ):
            raise ValueError(f"{field} must be a lowercase SHA-256 digest")
        return raw

    def timestamp(raw: object, field: str) -> str:
        if not isinstance(raw, str) or not raw.endswith("Z"):
            raise ValueError(f"{field} must be an RFC 3339 UTC timestamp")
        try:
            parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
        except ValueError as exc:
            raise ValueError(f"{field} must be an RFC 3339 UTC timestamp") from exc
        if parsed.tzinfo != timezone.utc:
            raise ValueError(f"{field} must be UTC")
        return raw

    receipt_raw = value.get("training_receipt")
    receipt: dict[str, str] | None
    if receipt_raw is None:
        receipt = None
    else:
        receipt_fields = {
            "receipt_payload_sha256",
            "event_hash",
            "key_id",
            "approval_subject_sha256",
            "training_run_id",
            "training_completed_at",
            "receipt_issued_at",
            "dataset_sha256",
            "environment_sha256",
            "environment_id",
            "adapter_id",
            "adapter_sha256",
            "training_backend",
            "base_model_id",
            "base_model_revision",
            "base_model_license_id",
            "base_model_license_evidence_sha256",
            "base_model_artifact_sha256",
            "base_model_artifact_manifest_sha256",
            "base_model_tokenizer_sha256",
            "base_model_artifact_format",
            "adapter_artifact_format",
            "adapter_checkpoint_sha256",
            "adapter_runtime_compatibility_sha256",
            "evaluation_protocol_sha256",
            "evaluation_run_sha256",
            "sealed_holdout_sha256",
            "qualification_evidence_sha256",
            "qualification_policy_sha256",
        }
        if not isinstance(receipt_raw, Mapping) or set(receipt_raw) != receipt_fields:
            raise ValueError("adapter training-receipt binding has an invalid shape")
        key_id = receipt_raw.get("key_id")
        revision = receipt_raw.get("base_model_revision")
        token_fields = (
            "training_run_id",
            "environment_id",
            "adapter_id",
            "training_backend",
            "base_model_id",
            "base_model_license_id",
            "base_model_artifact_format",
            "adapter_artifact_format",
        )
        if (
            not isinstance(key_id, str)
            or not re.fullmatch(r"[0-9a-f]{16}", key_id)
        ):
            raise ValueError("adapter training-receipt key id is invalid")
        if (
            not isinstance(revision, str)
            or not re.fullmatch(
                r"(?:[0-9a-f]{40}|[0-9a-f]{64}|sha256:[0-9a-f]{64})",
                revision,
            )
        ):
            raise ValueError("adapter base-model revision is invalid")
        if any(
            not isinstance(receipt_raw.get(field), str)
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}",
                str(receipt_raw.get(field)),
            )
            for field in token_fields
        ):
            raise ValueError("adapter training-receipt identity is invalid")
        receipt = {
            "receipt_payload_sha256": digest(
                receipt_raw.get("receipt_payload_sha256"),
                "training receipt payload",
            ),
            "event_hash": digest(
                receipt_raw.get("event_hash"), "training receipt event",
            ),
            "key_id": key_id,
            "approval_subject_sha256": digest(
                receipt_raw.get("approval_subject_sha256"),
                "training approval subject",
            ),
            "training_run_id": str(receipt_raw.get("training_run_id")),
            "training_completed_at": timestamp(
                receipt_raw.get("training_completed_at"),
                "training completion",
            ),
            "receipt_issued_at": timestamp(
                receipt_raw.get("receipt_issued_at"),
                "training receipt issuance",
            ),
            "dataset_sha256": digest(
                receipt_raw.get("dataset_sha256"),
                "training dataset",
            ),
            "environment_sha256": digest(
                receipt_raw.get("environment_sha256"),
                "training environment",
            ),
            "environment_id": str(receipt_raw.get("environment_id")),
            "adapter_id": str(receipt_raw.get("adapter_id")),
            "adapter_sha256": digest(
                receipt_raw.get("adapter_sha256"),
                "training adapter artifact",
            ),
            "training_backend": str(receipt_raw.get("training_backend")),
            "base_model_id": str(receipt_raw.get("base_model_id")),
            "base_model_revision": revision,
            "base_model_license_id": str(
                receipt_raw.get("base_model_license_id"),
            ),
            "base_model_license_evidence_sha256": digest(
                receipt_raw.get("base_model_license_evidence_sha256"),
                "training base-model license evidence",
            ),
            "base_model_artifact_sha256": digest(
                receipt_raw.get("base_model_artifact_sha256"),
                "training base-model artifact",
            ),
            "base_model_artifact_manifest_sha256": digest(
                receipt_raw.get("base_model_artifact_manifest_sha256"),
                "training base-model artifact manifest",
            ),
            "base_model_tokenizer_sha256": digest(
                receipt_raw.get("base_model_tokenizer_sha256"),
                "training base-model tokenizer",
            ),
            "base_model_artifact_format": str(
                receipt_raw.get("base_model_artifact_format"),
            ),
            "adapter_artifact_format": str(
                receipt_raw.get("adapter_artifact_format"),
            ),
            "adapter_checkpoint_sha256": digest(
                receipt_raw.get("adapter_checkpoint_sha256"),
                "training adapter checkpoint",
            ),
            "adapter_runtime_compatibility_sha256": digest(
                receipt_raw.get("adapter_runtime_compatibility_sha256"),
                "training adapter runtime compatibility",
            ),
            "evaluation_protocol_sha256": digest(
                receipt_raw.get("evaluation_protocol_sha256"),
                "training evaluation protocol",
            ),
            "evaluation_run_sha256": digest(
                receipt_raw.get("evaluation_run_sha256"),
                "training evaluation run",
            ),
            "sealed_holdout_sha256": digest(
                receipt_raw.get("sealed_holdout_sha256"),
                "training sealed holdout",
            ),
            "qualification_evidence_sha256": digest(
                receipt_raw.get("qualification_evidence_sha256"),
                "signed qualification evidence",
            ),
            "qualification_policy_sha256": digest(
                receipt_raw.get("qualification_policy_sha256"),
                "signed qualification policy",
            ),
        }

    qualification_raw = value.get("qualification")
    if not isinstance(qualification_raw, Mapping) or set(qualification_raw) != {
        "evidence_sha256",
        "policy_sha256",
        "run_id",
        "profile",
        "catalog_id",
        "catalog_sha256",
        "dataset_sha256",
        "evaluation_run_sha256",
        "sealed_holdout_sha256",
        "measured_at",
        "expires_at",
        "runtime_attestation_sha256",
        "engine",
        "engine_version",
        "context_tokens",
        "concurrency",
        "base_model_license_id",
        "base_model_license_evidence_sha256",
        "base_model_artifact_sha256",
        "base_model_artifact_manifest_sha256",
        "base_model_tokenizer_sha256",
        "adapter_checkpoint_sha256",
        "adapter_runtime_compatibility_sha256",
        "deployment_manifest_sha256",
        "container_or_lock_sha256",
        "hardware_profile_sha256",
        "base_model_id",
        "base_model_revision",
        "base_model_artifact_format",
        "adapter_artifact_format",
    }:
        raise ValueError("adapter qualification binding has an invalid shape")
    run_id = qualification_raw.get("run_id")
    profile = qualification_raw.get("profile")
    if (
        not isinstance(run_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}", run_id)
        or profile not in {"edge", "standard", "throughput"}
    ):
        raise ValueError("adapter qualification identity is invalid")
    qualification = {
        field: digest(qualification_raw.get(field), f"qualification {field}")
        for field in (
            "evidence_sha256",
            "policy_sha256",
            "catalog_sha256",
            "dataset_sha256",
            "evaluation_run_sha256",
            "sealed_holdout_sha256",
            "runtime_attestation_sha256",
            "base_model_license_evidence_sha256",
            "base_model_artifact_sha256",
            "base_model_artifact_manifest_sha256",
            "base_model_tokenizer_sha256",
            "adapter_checkpoint_sha256",
            "adapter_runtime_compatibility_sha256",
            "deployment_manifest_sha256",
            "container_or_lock_sha256",
            "hardware_profile_sha256",
        )
    }
    qualification_token_fields = (
        "base_model_id",
        "catalog_id",
        "engine",
        "engine_version",
        "base_model_license_id",
        "base_model_artifact_format",
        "adapter_artifact_format",
    )
    if any(
        not isinstance(qualification_raw.get(field), str)
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}",
            str(qualification_raw.get(field)),
        )
        for field in qualification_token_fields
    ):
        raise ValueError("adapter qualification artifact identity is invalid")
    model_revision = qualification_raw.get("base_model_revision")
    if (
        not isinstance(model_revision, str)
        or not re.fullmatch(r"[0-9a-f]{40}", model_revision)
    ):
        raise ValueError("adapter qualification base-model revision is invalid")
    qualification["run_id"] = run_id
    qualification["profile"] = str(profile)
    qualification["measured_at"] = timestamp(
        qualification_raw.get("measured_at"),
        "qualification measurement",
    )
    qualification["expires_at"] = timestamp(
        qualification_raw.get("expires_at"),
        "qualification expiry",
    )
    for integer_field in ("context_tokens", "concurrency"):
        raw_integer = qualification_raw.get(integer_field)
        if (
            not isinstance(raw_integer, int)
            or isinstance(raw_integer, bool)
            or raw_integer <= 0
        ):
            raise ValueError(
                f"qualification {integer_field} must be a positive integer",
            )
        qualification[integer_field] = raw_integer
    for token_field in qualification_token_fields:
        qualification[token_field] = str(qualification_raw.get(token_field))
    qualification["base_model_revision"] = model_revision
    return {
        "schema": MODEL_IMPROVEMENT_BINDING_SCHEMA,
        "policy_sha256": digest(
            value.get("policy_sha256"),
            "model-improvement policy",
        ),
        "training_receipt": receipt,
        "qualification": qualification,
    }


def _authority_payload(
    pointer: dict, *, artifact_identity: str, ledger_path: Path | str,
) -> str:
    """Canonical bytes approved for a production-routable adapter pointer.

    Generation and activation time are transaction metadata.  Every field that
    can change what is served is included, including the complete deployment
    attestation and immutable artifact/store identity.
    """
    if (not isinstance(artifact_identity, str) or not artifact_identity
            or len(artifact_identity) > 4096
            or any(ord(ch) < 32 for ch in artifact_identity)):
        raise ValueError("adapter authority payload has an invalid artifact identity")
    if not isinstance(pointer, dict):
        raise ValueError("adapter authority payload requires a pointer object")
    resolved_ledger_path = Path(ledger_path).expanduser()
    if not resolved_ledger_path.is_absolute():
        raise ValueError("adapter authority payload requires an absolute ledger path")
    resolved_ledger_path = resolved_ledger_path.resolve()
    serving = pointer.get("serving")
    if not isinstance(serving, dict):
        raise ValueError("adapter authority payload requires a serving binding")
    bound_pointer = {
        "authority": "governed-v1",
        "tenant_id": _validated_tenant_id(pointer.get("tenant_id", "")),
        "promotion_record_id": str(pointer.get("promotion_record_id", "")),
        "adapter_id": str(pointer.get("adapter_id", "")),
        "base_model": str(pointer.get("base_model", "")),
        "dataset_sha256": str(pointer.get("dataset_sha256", "")),
        "payload_sha256": str(pointer.get("payload_sha256", "")),
        "serving": serving,
    }
    if "model_improvement" in pointer:
        bound_pointer["model_improvement"] = _validated_model_improvement_binding(
            pointer["model_improvement"],
        )
    try:
        payload = json.dumps(
            {
                "version": ADAPTER_AUTHORITY_PAYLOAD_VERSION,
                "artifact_identity": artifact_identity,
                "ledger_path": str(resolved_ledger_path),
                "pointer": bound_pointer,
            },
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("adapter authority payload is not canonical JSON") from exc
    if len(payload.encode("utf-8")) > MAX_APPROVAL_PAYLOAD_BYTES:
        raise ValueError("adapter authority payload exceeds the size limit")
    return payload


def _server_approval_key_registry() -> dict[str, str]:
    """Return deployment-owned adapter-promotion roots keyed by fingerprint."""
    from . import approval_signing

    try:
        values = approval_signing.trusted_global_approver_keys()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(
            "adapter promotion trust registry is unavailable",
        ) from exc
    try:
        canonical_keys = _validated_approval_public_keys(values)
    except ValueError as exc:
        raise ValueError(
            "adapter promotion trust registry is empty or invalid",
        ) from exc
    registry: dict[str, str] = {}
    for public_key in canonical_keys:
        identifier = approval_signing.key_id(public_key)
        existing = registry.get(identifier)
        if existing is not None and existing != public_key:
            raise ValueError("adapter promotion trust registry has a collision")
        registry[identifier] = public_key
    return registry


def _validate_pointer_receipt(
    value: dict | None, *, tenant_id: str, serving: dict | None, record_id: str,
) -> dict:
    """Validate the durable receipt binding required for production routing."""
    if not isinstance(value, dict) or value.get("version") not in {2, 3}:
        raise ValueError("governed adapter pointer has no valid receipt binding")
    receipt = dict(value)
    common_fields = {
        "version",
        "tenant_id",
        "record_id",
        "ledger_path",
        "payload_sha256",
        "approval_signature",
        "approved_payload",
        "artifact_identity",
    }
    expected_fields = (
        common_fields | {"approval_pubkey"}
        if receipt["version"] == 2
        else common_fields | {"approval_key_id"}
    )
    if set(receipt) != expected_fields:
        raise ValueError("adapter receipt binding has missing or unexpected fields")
    if _validated_tenant_id(receipt.get("tenant_id", "")) != tenant_id:
        raise ValueError("adapter receipt binding belongs to another tenant")
    if receipt.get("record_id") != record_id:
        raise ValueError("adapter receipt binding has the wrong record id")
    raw_path = receipt.get("ledger_path")
    if (not isinstance(raw_path, str) or not raw_path or len(raw_path) > 4096
            or any(ord(ch) < 32 for ch in raw_path)):
        raise ValueError("adapter receipt binding has an invalid ledger path")
    ledger_path = Path(raw_path).expanduser()
    if not ledger_path.is_absolute():
        raise ValueError("adapter receipt ledger path must be absolute")
    receipt["ledger_path"] = str(ledger_path.resolve())
    digest = receipt.get("payload_sha256")
    if (not isinstance(digest, str) or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)):
        raise ValueError("adapter receipt binding has an invalid payload digest")
    signature = receipt.get("approval_signature")
    if (not isinstance(signature, str) or not signature or len(signature) > 8192
            or any(ord(ch) < 32 for ch in signature)):
        raise ValueError("adapter receipt binding has an invalid approval signature")
    registry = _server_approval_key_registry()
    if receipt["version"] == 2:
        public_key = receipt.get("approval_pubkey")
        canonical_key = _validated_approval_public_keys(
            [public_key] if isinstance(public_key, str) else None,
        )[0]
        from . import approval_signing

        approval_key_id = approval_signing.key_id(canonical_key)
        if registry.get(approval_key_id) != canonical_key:
            raise ValueError(
                "adapter receipt approval key is not server-trusted",
            )
        receipt.pop("approval_pubkey", None)
        receipt["version"] = 3
        receipt["approval_key_id"] = approval_key_id
    else:
        approval_key_id = receipt.get("approval_key_id")
        if (
            not isinstance(approval_key_id, str)
            or not re.fullmatch(r"[0-9a-f]{16}", approval_key_id)
            or approval_key_id not in registry
        ):
            raise ValueError(
                "adapter receipt approval key is not server-trusted",
            )
    approved_payload = receipt.get("approved_payload")
    if (not isinstance(approved_payload, str) or not approved_payload
            or len(approved_payload.encode("utf-8")) > MAX_APPROVAL_PAYLOAD_BYTES):
        raise ValueError("adapter receipt binding has an invalid approved payload")
    if hashlib.sha256(approved_payload.encode("utf-8")).hexdigest() != digest:
        raise ValueError("adapter receipt approved payload digest does not match")
    artifact_identity = receipt.get("artifact_identity")
    if (not isinstance(artifact_identity, str) or not artifact_identity
            or len(artifact_identity) > 4096
            or any(ord(ch) < 32 for ch in artifact_identity)):
        raise ValueError("adapter receipt binding has an invalid artifact identity")
    if isinstance(serving, dict) and serving.get("mode") == "modelfile":
        _validate_deployment_attestation(serving)
    return receipt


class AdapterStore:
    """Filesystem store for adapter payloads plus the ACTIVE pointer.

    Activation is a pointer swap, never a payload mutation.  One atomic
    ``pointer-state.json`` owns active + previous; ``active.json`` and
    ``previous.json`` are compatibility projections.  ``rollback()`` is a
    byte-identical one-step restore -- the same reversibility contract the
    solver rung meets with ``apply_and_archive``/``rollback_solver``."""

    def __init__(self, root: Path | str | None = None, *, tenant_id: str | None = None):
        self.tenant_id = _validated_tenant_id(
            _active_tenant_id() if tenant_id is None else tenant_id)
        if root is None:
            root = default_store_root(tenant_id=self.tenant_id)
        self.root = Path(root)

    # -- pointers ------------------------------------------------------------
    @property
    def _state_path(self) -> Path:
        return self.root / POINTER_STATE_BASENAME

    @property
    def artifact_identity(self) -> str:
        root = os.path.normcase(str(self.root.expanduser().resolve()))
        root_tag = hashlib.sha256(root.encode("utf-8")).hexdigest()[:24]
        tenant_tag = (_tenant_tag(self.tenant_id) if self.tenant_id else "shared")
        return f"adapter-pointer:{tenant_tag}:{root_tag}"

    def _read_json_locked(self, basename: str) -> dict | None:
        path = self.root / basename
        if not path.exists():
            return None
        from .file_lock import atomic_read_text
        value = json.loads(atomic_read_text(path))
        if not isinstance(value, dict):
            raise ValueError(f"adapter pointer {path} is not an object")
        return value

    def _validate_pointer(self, value: dict | None, *, label: str) -> dict | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError(f"adapter {label} pointer is not an object")
        pointer = dict(value)
        tenant = _validated_tenant_id(pointer.get("tenant_id", ""))
        if tenant != self.tenant_id:
            raise ValueError(
                f"adapter {label} pointer tenant mismatch: expected "
                f"{self.tenant_id or 'shared'!r}, got {tenant or 'shared'!r}")
        for key in ("adapter_id", "base_model", "promotion_record_id"):
            item = pointer.get(key)
            if not isinstance(item, str) or not item.strip() or len(item) > 2048:
                raise ValueError(f"adapter {label} pointer has invalid {key}")
        digest = pointer.get("payload_sha256", "")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)):
            raise ValueError(f"adapter {label} pointer has invalid payload_sha256")
        generation = pointer.get("generation", 0)
        if (not isinstance(generation, int) or isinstance(generation, bool)
                or generation < 0):
            raise ValueError(f"adapter {label} pointer has invalid generation")
        activated_at = pointer.get("activated_at")
        if (not isinstance(activated_at, (int, float)) or isinstance(activated_at, bool)
                or not math.isfinite(float(activated_at)) or float(activated_at) < 0):
            raise ValueError(f"adapter {label} pointer has invalid activated_at")
        serving = pointer.get("serving")
        if serving is not None and not isinstance(serving, dict):
            raise ValueError(f"adapter {label} pointer has invalid serving binding")
        if (isinstance(serving, dict)
                and _validated_tenant_id(serving.get("tenant_id", "")) != self.tenant_id):
            raise ValueError(f"adapter {label} serving binding belongs to another tenant")
        if isinstance(serving, dict) and serving.get("model_name") is not None:
            expected_name = tuned_model_name(AdapterManifest(
                adapter_id=pointer["adapter_id"],
                base_model=pointer["base_model"],
                trainer="",
                dataset_sha256="",
                examples=0,
                payload_sha256=pointer["payload_sha256"],
                tenant_id=self.tenant_id,
            ))
            if serving.get("model_name") != expected_name:
                raise ValueError(f"adapter {label} pointer has a mismatched model name")
        authority = pointer.get("authority", "legacy-unbound")
        if authority not in {"legacy-unbound", "dev-unbound", "governed-v1"}:
            raise ValueError(f"adapter {label} pointer has invalid serving authority")
        dataset_digest = pointer.get("dataset_sha256", "")
        if (authority == "governed-v1"
                and (not isinstance(dataset_digest, str)
                     or len(dataset_digest) != 64
                     or any(ch not in "0123456789abcdef" for ch in dataset_digest))):
            raise ValueError(f"adapter {label} pointer has invalid dataset_sha256")
        if dataset_digest:
            pointer["dataset_sha256"] = dataset_digest
        receipt = pointer.get("receipt")
        if authority == "governed-v1":
            expected_mode = (
                "modelfile" if _base_provider(pointer["base_model"])
                in _SERVING_PROVIDERS else "manual")
            if not isinstance(serving, dict) or serving.get("mode") != expected_mode:
                raise ValueError(
                    f"adapter {label} governed pointer has no valid serving mode")
            pointer["receipt"] = _validate_pointer_receipt(
                receipt, tenant_id=self.tenant_id,
                serving=serving, record_id=pointer["promotion_record_id"])
        elif receipt is not None:
            raise ValueError(f"adapter {label} unbound pointer carries a receipt")
        if "authority" in pointer:
            pointer["authority"] = authority
        return pointer

    def _validate_rollback_intent(self, value: dict | None) -> dict | None:
        if value is None:
            return None
        if not isinstance(value, dict) or value.get("version") != 1:
            raise ValueError("adapter rollback intent is invalid")
        intent = dict(value)
        if _validated_tenant_id(intent.get("tenant_id", "")) != self.tenant_id:
            raise ValueError("adapter rollback intent belongs to another tenant")
        for key in ("transaction_id", "record_id"):
            item = intent.get(key)
            if (not isinstance(item, str) or not item.strip() or len(item) > 256
                    or any(ord(ch) < 32 for ch in item)):
                raise ValueError(f"adapter rollback intent has invalid {key}")
        prepared_at = intent.get("prepared_at")
        if (not isinstance(prepared_at, (int, float)) or isinstance(prepared_at, bool)
                or not math.isfinite(float(prepared_at)) or float(prepared_at) < 0):
            raise ValueError("adapter rollback intent has invalid prepared_at")
        from .self_improvement import ArtifactRevision
        for key in ("before", "after"):
            raw = intent.get(key)
            if not isinstance(raw, dict):
                raise ValueError(f"adapter rollback intent has invalid {key} revision")
            revision = ArtifactRevision(**raw)
            if revision.identity != self.artifact_identity:
                raise ValueError("adapter rollback intent has the wrong artifact identity")
            intent[key] = revision.to_dict()
        if intent["before"] == intent["after"]:
            raise ValueError("adapter rollback intent is a no-op")
        return intent

    def _read_state_locked(self, *, verify_serving: bool = False) -> _PointerState:
        raw = self._read_json_locked(POINTER_STATE_BASENAME)
        if raw is not None:
            if raw.get("version") != 1:
                raise ValueError("adapter pointer state has an unsupported version")
            tenant = _validated_tenant_id(raw.get("tenant_id", ""))
            if tenant != self.tenant_id:
                raise ValueError("adapter pointer state belongs to another tenant")
            state = _PointerState(
                active=self._validate_pointer(raw.get("active"), label="active"),
                previous=self._validate_pointer(raw.get("previous"), label="previous"),
                pending_rollback=self._validate_rollback_intent(
                    raw.get("pending_rollback")),
            )
        else:
            # Backward-compatible one-time read of pre-transaction stores.  The
            # next activation/rollback atomically publishes pointer-state.json.
            state = _PointerState(
                active=self._validate_pointer(
                    self._read_json_locked(ACTIVE_BASENAME), label="active"),
                previous=self._validate_pointer(
                    self._read_json_locked(PREVIOUS_BASENAME), label="previous"),
                pending_rollback=None,
            )
        if verify_serving and state.active is not None:
            _verify_serving_binding(state.active.get("serving"))
        return state

    def _state(self, *, strict: bool, verify_serving: bool = False) -> _PointerState:
        from .file_lock import cross_process_lock
        try:
            with cross_process_lock(self._state_path, strict=True):
                return self._read_state_locked(verify_serving=verify_serving)
        except Exception:
            if strict:
                raise
            # A corrupt, cross-tenant, or incomplete pointer must never route a
            # request.  The privileged transaction path uses strict=True and
            # therefore cannot mistake it for an empty store.
            log.warning("unreadable adapter pointer state %s", self.root, exc_info=True)
            return _PointerState()

    def _write_state_locked(self, state: _PointerState) -> None:
        active = self._validate_pointer(state.active, label="active")
        previous = self._validate_pointer(state.previous, label="previous")
        pending_rollback = self._validate_rollback_intent(state.pending_rollback)
        _atomic_write_json(self._state_path, {
            "version": 1,
            "tenant_id": self.tenant_id,
            "active": active,
            "previous": previous,
            "pending_rollback": pending_rollback,
        })
        # active.json/previous.json remain compatibility projections.  The
        # single atomic pointer-state file above is authoritative, so a crash
        # between projection writes cannot create a partial logical state.
        try:
            if active is None:
                (self.root / ACTIVE_BASENAME).unlink(missing_ok=True)
            else:
                _atomic_write_json(self.root / ACTIVE_BASENAME, active)
            if previous is None:
                (self.root / PREVIOUS_BASENAME).unlink(missing_ok=True)
            else:
                _atomic_write_json(self.root / PREVIOUS_BASENAME, previous)
        except Exception:
            log.warning("adapter compatibility pointer projection failed", exc_info=True)

    def _revision(self, state: _PointerState):
        from .self_improvement import ArtifactRevision
        canonical = json.dumps(
            {"tenant_id": self.tenant_id, "active": state.active,
             "previous": state.previous},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        generation = 0
        if state.active is not None:
            generation = int(state.active.get("generation", 0))
        return ArtifactRevision(
            identity=self.artifact_identity,
            sha256=digest,
            version=f"{generation}:{digest[:24]}",
        )

    def inspect_revision(self, identity: str):
        """Strictly inspect pointer + serving evidence for crash recovery."""
        if identity != self.artifact_identity:
            raise ValueError("unexpected adapter artifact identity")
        state = self._state(strict=True, verify_serving=True)
        return self._revision(state)

    @contextmanager
    def transaction_locked(self):
        """Hold the strict artifact lock across ledger and pointer transitions."""
        from .file_lock import cross_process_lock
        with cross_process_lock(self._state_path, strict=True):
            yield

    def active(self) -> dict | None:
        """The active promoted adapter pointer, or None."""
        return self._state(strict=False, verify_serving=True).active

    def previous(self) -> dict | None:
        return self._state(strict=False).previous

    def path_for(self, adapter_id: str) -> Path:
        if not isinstance(adapter_id, str) or not _ADAPTER_ID_RE.fullmatch(adapter_id):
            raise ValueError("adapter payload id is invalid")
        return self.root / "payloads" / adapter_id

    def stage_payload(
        self, adapter_dir: Path | str, manifest: AdapterManifest,
    ) -> tuple[Path, AdapterManifest]:
        """Copy a reviewed payload into a tenant-bound content-addressed root."""
        _require_manifest_tenant(manifest, self.tenant_id)
        source = Path(adapter_dir)
        review = review_adapter_payload(source)
        if not review.ok:
            raise ValueError(review.reason)
        digest = payload_digest_dir(source)
        if manifest.payload_sha256 and manifest.payload_sha256 != digest:
            raise ValueError("adapter payload changed before staging")
        staged_manifest = replace(manifest, payload_sha256=digest)
        _validate_manifest(staged_manifest)
        identity_blob = json.dumps({
            "tenant_id": self.tenant_id,
            "adapter_id": staged_manifest.adapter_id,
            "base_model": staged_manifest.base_model,
            "dataset_sha256": staged_manifest.dataset_sha256,
            "payload_sha256": digest,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        artifact_id = hashlib.sha256(identity_blob).hexdigest()
        payloads = self.root / "payloads"
        destination = payloads / artifact_id
        from .file_lock import (
            cross_process_lock,
            ensure_private_directory,
        )
        with cross_process_lock(destination, strict=True):
            if destination.exists():
                loaded = AdapterManifest.load(destination)
                if loaded.to_dict() != staged_manifest.to_dict():
                    raise ValueError("content-addressed adapter manifest collision")
                if payload_digest_dir(destination) != digest:
                    raise ValueError("content-addressed adapter payload is corrupt")
                return destination, loaded
            payloads.mkdir(parents=True, exist_ok=True)
            ensure_private_directory(payloads)
            temporary = Path(tempfile.mkdtemp(prefix=f".{artifact_id}-", dir=payloads))
            ensure_private_directory(temporary)
            try:
                for rel, src, info in _bounded_payload_files(source):
                    if rel.name in {MANIFEST_BASENAME, SERVING_BASENAME}:
                        continue
                    dst = temporary / rel
                    _copy_payload_file(src, dst, info)
                if payload_digest_dir(temporary) != digest:
                    raise ValueError("adapter payload changed during staging")
                staged_manifest.save(temporary)
                os.replace(temporary, destination)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary, ignore_errors=True)
        return destination, staged_manifest

    def plan_activation(
        self, manifest: AdapterManifest, *, record_id: str,
        activated_at: float | None = None, serving: dict | None = None,
        model_improvement: dict[str, Any] | None = None,
    ) -> AdapterActivationPlan:
        """Snapshot an exact tenant-bound before/after pointer transition."""
        with self.transaction_locked():
            return self._plan_activation_locked(
                manifest, record_id=record_id, activated_at=activated_at,
                serving=serving, receipt=None,
                model_improvement=model_improvement)

    def _plan_activation_locked(
        self, manifest: AdapterManifest, *, record_id: str,
        activated_at: float | None = None, serving: dict | None = None,
        receipt: dict | None = None,
        model_improvement: dict[str, Any] | None = None,
    ) -> AdapterActivationPlan:
        _require_manifest_tenant(manifest, self.tenant_id)
        _validate_manifest(manifest)
        if (not isinstance(record_id, str) or not record_id.strip()
                or len(record_id) > 256 or any(ord(ch) < 32 for ch in record_id)):
            raise ValueError("adapter promotion record id is invalid")
        at = time.time() if activated_at is None else float(activated_at)
        state = self._read_state_locked(verify_serving=True)
        if state.pending_rollback is not None:
            raise RuntimeError("adapter rollback recovery is required")
        if (state.active is not None
                and state.active.get("authority") == "governed-v1"):
            _verify_authoritative_pointer(
                state.active, artifact_identity=self.artifact_identity)
        generation = 1
        if state.active is not None:
            generation = int(state.active.get("generation", 0)) + 1
        pointer = {
            "adapter_id": manifest.adapter_id,
            "base_model": manifest.base_model,
            "dataset_sha256": manifest.dataset_sha256,
            "payload_sha256": manifest.payload_sha256,
            "promotion_record_id": record_id,
            "tenant_id": self.tenant_id,
            "generation": generation,
            "activated_at": at,
            "authority": "governed-v1" if receipt is not None else "dev-unbound",
        }
        if serving is not None:
            pointer["serving"] = dict(serving)
        if model_improvement is not None:
            pointer["model_improvement"] = _validated_model_improvement_binding(
                model_improvement,
            )
        if receipt is not None:
            pointer["receipt"] = _validate_pointer_receipt(
                receipt, tenant_id=self.tenant_id, serving=serving,
                record_id=record_id)
        after_state = _PointerState(
            active=pointer, previous=state.active, pending_rollback=None)
        return AdapterActivationPlan(
            before=self._revision(state), after=self._revision(after_state),
            pointer=pointer, state=after_state)

    def apply_activation(self, plan: AdapterActivationPlan) -> dict:
        """CAS-install a prepared activation and inspect the exact after state."""
        with self.transaction_locked():
            self._apply_activation_locked(plan)
        return dict(plan.pointer)

    def _apply_activation_locked(self, plan: AdapterActivationPlan):
        current = self._read_state_locked(verify_serving=True)
        if current.pending_rollback is not None:
            raise RuntimeError("adapter rollback recovery is required")
        if self._revision(current) != plan.before:
            raise RuntimeError("adapter activation CAS conflict")
        if plan.state.active != plan.pointer or plan.state.pending_rollback is not None:
            raise RuntimeError("adapter activation plan is internally inconsistent")
        _verify_serving_binding(plan.pointer.get("serving"))
        self._write_state_locked(plan.state)
        observed = self._read_state_locked(verify_serving=True)
        if self._revision(observed) != plan.after:
            raise RuntimeError("adapter activation inspection mismatch")
        return self._revision(observed)

    def activate(self, manifest: AdapterManifest, *, record_id: str) -> dict:
        """Low-level pointer activation retained for local/dev compatibility.

        Governed production promotion uses ``plan_activation`` + durable ledger
        PREPARE + ``apply_activation`` + COMMIT below.
        """
        return self.apply_activation(self.plan_activation(manifest, record_id=record_id))

    def rollback(self) -> dict | None:
        """One-step revert to the previously active pointer. Returns the
        restored pointer (None = nothing to restore). With no previous pointer
        the active adapter is simply deactivated -- the base model serves."""
        from .file_lock import cross_process_lock
        with cross_process_lock(self._state_path, strict=True):
            state = self._read_state_locked(verify_serving=True)
            if state.pending_rollback is not None:
                raise RuntimeError("adapter rollback recovery is required")
            if state.previous is not None:
                _verify_serving_binding(state.previous.get("serving"))
                if state.previous.get("authority") == "governed-v1":
                    _verify_authoritative_pointer(
                        state.previous, artifact_identity=self.artifact_identity)
            next_state = _PointerState(
                active=state.previous, previous=None, pending_rollback=None)
            self._write_state_locked(next_state)
            return next_state.active


# The local serving providers we know how to bind a promoted adapter for (the
# Ollama Modelfile ADAPTER directive; 'local' is the registry alias for ollama).
# A base on any other provider promotes and ledgers normally but is NOT auto-
# routed -- the operator wires its serving -- so effective_model_spec never
# silently switches a vLLM/TGI call to the Ollama client.
_SERVING_PROVIDERS: frozenset[str] = frozenset({"ollama", "local"})


def _base_provider(spec: str) -> str:
    return spec.split(":", 1)[0].strip().lower() if ":" in spec else ""


# --- cheap hot-path resolution (config + active pointer, memoized by mtime) --------
#
# _parse_spec calls effective_model_spec on EVERY LLM call (and once per admin
# allow-list entry). A naive get_adapter_rung() re-interpolates the whole config
# tree each time; these caches reduce the disabled default path to a few stat()
# calls and the enabled path to one stat() of active.json until it actually
# changes. Keyed by file stat signatures so a wizard rewrite or a promotion/
# rollback invalidates them immediately.

_CFG_CACHE: dict[str, Any] = {}
_ACTIVE_CACHE: dict[str, Any] = {}


def _reset_caches() -> None:
    """Test hook: drop the memoized config/pointer state."""
    _CFG_CACHE.clear()
    _ACTIVE_CACHE.clear()


def _stat_sig(path: Path) -> tuple:
    try:
        st = os.stat(path)
        return (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return (str(path), -1, -1)


def _serving_integrity_stamp(binding: dict | None) -> tuple | None:
    """Cheap metadata witness for an already-verified immutable payload.

    Transaction and cache-miss paths still hash every byte.  Cache hits stat
    the bounded file set; any content write, replacement, chmod, or tree change
    changes this witness and forces a cryptographic re-verification.
    """
    if binding is None:
        return None
    if not isinstance(binding, dict):
        raise ValueError("adapter serving binding is not an object")
    raw = binding.get("adapter_dir")
    if not isinstance(raw, str) or not raw:
        raise ValueError("adapter serving binding has no payload directory")
    root = Path(raw)
    if _is_unsafe_link(root):
        raise ValueError("adapter serving payload root is unsafe")
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode):
        raise ValueError("adapter serving payload root is not a directory")
    files = tuple(
        (str(relative), _stat_identity(info))
        for relative, _path, info in _bounded_payload_files(root)
    )
    return (_stat_identity(root_info), files)


def _receipt_integrity_stamp(pointer: dict | None) -> tuple | None:
    if pointer is None:
        return None
    receipt = pointer.get("receipt")
    if not isinstance(receipt, dict):
        return None
    path = Path(str(receipt.get("ledger_path", "")))
    return (_stat_sig(path), _stat_sig(Path(f"{path}.journal")))


def _model_improvement_runtime_requirement(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the exact content-free runtime a provisioner must observe."""
    binding = _validated_model_improvement_binding(value)
    receipt = binding["training_receipt"]
    qualification = binding["qualification"]
    if receipt is None or qualification is None:
        raise ValueError("model-improvement runtime requires signed qualification")
    return {
        "schema": "lightwork.serving-runtime-attestation.v1",
        "runtime_attestation_sha256": qualification[
            "runtime_attestation_sha256"
        ],
        "engine": qualification["engine"],
        "engine_version": qualification["engine_version"],
        "base_model_artifact_format": qualification[
            "base_model_artifact_format"
        ],
        "base_model_artifact_sha256": qualification[
            "base_model_artifact_sha256"
        ],
        "base_model_artifact_manifest_sha256": qualification[
            "base_model_artifact_manifest_sha256"
        ],
        "base_model_tokenizer_sha256": qualification[
            "base_model_tokenizer_sha256"
        ],
        "adapter_artifact_format": qualification["adapter_artifact_format"],
        "adapter_sha256": receipt["adapter_sha256"],
        "adapter_checkpoint_sha256": qualification[
            "adapter_checkpoint_sha256"
        ],
        "adapter_runtime_compatibility_sha256": qualification[
            "adapter_runtime_compatibility_sha256"
        ],
        "deployment_manifest_sha256": qualification[
            "deployment_manifest_sha256"
        ],
        "container_or_lock_sha256": qualification["container_or_lock_sha256"],
        "hardware_profile_sha256": qualification["hardware_profile_sha256"],
        "context_tokens": qualification["context_tokens"],
        "concurrency": qualification["concurrency"],
    }


def _revalidate_model_improvement_pointer(  # noqa: C901
    pointer: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> None:
    """Recheck time, catalog, receipt, and serving-runtime bindings.

    This runs on the routing hot path, including cache hits. A promotion-time
    qualification is not an indefinite serving authorization.
    """
    raw = pointer.get("model_improvement")
    if raw is None:
        return
    binding = _validated_model_improvement_binding(raw)
    receipt = binding["training_receipt"]
    qualification = binding["qualification"]
    if receipt is None or qualification is None:
        raise ValueError(
            "model-improvement routing requires receipt and qualification bindings",
        )
    current_policy = _model_improvement_policy()
    if not current_policy.get("enable"):
        raise ValueError("model-improvement serving policy is disabled")
    if (
        binding["policy_sha256"]
        != _model_improvement_policy_digest(current_policy)
    ):
        raise ValueError("model-improvement serving policy differs from promotion")

    from .training.qualification import (
        MAX_FUTURE_SKEW,
        RuntimeEvidence,
        qualification_expires_at,
        runtime_attestation_sha256,
    )
    from .training.specialist_models import (
        load_catalog,
        matches_catalog_artifact,
    )

    measured_at = datetime.fromisoformat(
        qualification["measured_at"][:-1] + "+00:00",
    )
    expires_at = datetime.fromisoformat(
        qualification["expires_at"][:-1] + "+00:00",
    )
    current = now or datetime.now(timezone.utc)
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise ValueError("model-improvement routing clock must be timezone-aware")
    current = current.astimezone(timezone.utc)
    if (
        qualification["expires_at"]
        != qualification_expires_at(qualification["measured_at"])
    ):
        raise ValueError("qualification expiry is not derived from its measurement")
    if measured_at > current + MAX_FUTURE_SKEW:
        raise ValueError("qualification measurement is future-dated")
    if expires_at <= current:
        raise ValueError("qualification has expired")

    catalog = load_catalog()
    if qualification["catalog_sha256"] != catalog.digest:
        raise ValueError("qualification catalog is no longer current")
    candidate = catalog.get(qualification["catalog_id"])
    if qualification["base_model_license_id"] != candidate.license_id:
        raise ValueError("qualification license differs from the current catalog")
    if qualification["context_tokens"] > candidate.context_tokens:
        raise ValueError("qualification context exceeds the current catalog maximum")
    if not matches_catalog_artifact(
        candidate,
        repository_id=qualification["base_model_id"],
        revision=qualification["base_model_revision"],
        artifact_format=qualification["base_model_artifact_format"],
    ):
        raise ValueError("qualification artifact is absent from the current catalog")

    runtime = RuntimeEvidence(
        engine=qualification["engine"],
        engine_version=qualification["engine_version"],
        base_model_artifact_format=qualification["base_model_artifact_format"],
        base_model_artifact_sha256=qualification["base_model_artifact_sha256"],
        base_model_artifact_manifest_sha256=(
            qualification["base_model_artifact_manifest_sha256"]
        ),
        base_model_tokenizer_sha256=qualification["base_model_tokenizer_sha256"],
        adapter_artifact_format=qualification["adapter_artifact_format"],
        adapter_sha256=str(pointer.get("payload_sha256") or ""),
        adapter_checkpoint_sha256=qualification["adapter_checkpoint_sha256"],
        adapter_runtime_compatibility_sha256=(
            qualification["adapter_runtime_compatibility_sha256"]
        ),
        deployment_manifest_sha256=qualification["deployment_manifest_sha256"],
        container_or_lock_sha256=qualification["container_or_lock_sha256"],
        hardware_profile_sha256=qualification["hardware_profile_sha256"],
        context_tokens=qualification["context_tokens"],
        concurrency=qualification["concurrency"],
    )
    runtime_digest = runtime_attestation_sha256(runtime)
    if runtime_digest != qualification["runtime_attestation_sha256"]:
        raise ValueError("qualification runtime attestation is inconsistent")

    exact_receipt_values = {
        "training_run_id": qualification["run_id"],
        "dataset_sha256": qualification["dataset_sha256"],
        "base_model_id": qualification["base_model_id"],
        "base_model_revision": qualification["base_model_revision"],
        "base_model_license_id": qualification["base_model_license_id"],
        "base_model_license_evidence_sha256": (
            qualification["base_model_license_evidence_sha256"]
        ),
        "base_model_artifact_sha256": qualification["base_model_artifact_sha256"],
        "base_model_artifact_manifest_sha256": (
            qualification["base_model_artifact_manifest_sha256"]
        ),
        "base_model_tokenizer_sha256": qualification["base_model_tokenizer_sha256"],
        "base_model_artifact_format": qualification["base_model_artifact_format"],
        "adapter_artifact_format": qualification["adapter_artifact_format"],
        "adapter_checkpoint_sha256": qualification["adapter_checkpoint_sha256"],
        "adapter_runtime_compatibility_sha256": (
            qualification["adapter_runtime_compatibility_sha256"]
        ),
        "evaluation_run_sha256": qualification["evaluation_run_sha256"],
        "sealed_holdout_sha256": qualification["sealed_holdout_sha256"],
        "qualification_evidence_sha256": qualification["evidence_sha256"],
        "qualification_policy_sha256": qualification["policy_sha256"],
    }
    if any(receipt.get(key) != value for key, value in exact_receipt_values.items()):
        raise ValueError("qualification no longer matches its signed training receipt")
    if (
        receipt["adapter_id"] != pointer.get("adapter_id")
        or receipt["adapter_sha256"] != pointer.get("payload_sha256")
        or receipt["dataset_sha256"] != pointer.get("dataset_sha256")
        or receipt["base_model_id"] != _model_id(str(pointer.get("base_model") or ""))
        or receipt["dataset_sha256"] != qualification["dataset_sha256"]
    ):
        raise ValueError("model-improvement pointer relabels signed provenance")

    serving = pointer.get("serving")
    if not isinstance(serving, Mapping):
        raise ValueError("model-improvement pointer has no serving binding")
    mode = serving.get("mode")
    if mode == "modelfile" and qualification["engine"].lower() != "ollama":
        raise ValueError("Ollama routing requires an Ollama qualification")
    if mode not in {"manual", "modelfile"}:
        raise ValueError("model-improvement serving mode is unsupported")
    if mode == "modelfile":
        deployment = serving.get("deployment")
        if not isinstance(deployment, Mapping):
            raise ValueError("model-improvement routing has no deployment attestation")
        required_runtime = _model_improvement_runtime_requirement(binding)
        if (
            deployment.get("model_improvement_runtime") != required_runtime
            or deployment.get("model_improvement_runtime_sha256")
            != runtime_digest
        ):
            raise ValueError("serving runtime differs from the qualified runtime")


def _verify_authoritative_pointer(pointer: dict, *, artifact_identity: str) -> None:
    """Cryptographically bind the exact routed pointer to its durable receipt."""
    if pointer.get("authority") != "governed-v1":
        raise ValueError("adapter pointer is legacy/development state, not serving authority")
    receipt = _validate_pointer_receipt(
        pointer.get("receipt"),
        tenant_id=_validated_tenant_id(pointer.get("tenant_id", "")),
        serving=pointer.get("serving"),
        record_id=str(pointer.get("promotion_record_id", "")))
    if receipt["artifact_identity"] != artifact_identity:
        raise ValueError("adapter receipt belongs to another artifact store")
    approved_payload = _authority_payload(
        pointer, artifact_identity=artifact_identity,
        ledger_path=receipt["ledger_path"])
    if approved_payload != receipt["approved_payload"]:
        raise ValueError("adapter pointer differs from the exact approved serving payload")
    approved_digest = hashlib.sha256(approved_payload.encode("utf-8")).hexdigest()
    if approved_digest != receipt["payload_sha256"]:
        raise ValueError("adapter pointer approved-payload digest does not match")
    _revalidate_model_improvement_pointer(pointer)
    from .self_improvement import PromotionLedger
    ledger = PromotionLedger(path=Path(receipt["ledger_path"]))
    record = ledger.get(receipt["record_id"])
    if (record is None or record.rolled_back or record.rung != "weights"
            or record.payload_sha256 != approved_digest
            or record.approval_signature != receipt["approval_signature"]
            or not record.approver_id
            or _validated_tenant_id(record.provenance.get("tenant_id", ""))
            != _validated_tenant_id(pointer.get("tenant_id", ""))):
        raise ValueError("adapter pointer has no matching committed promotion receipt")
    from . import approval_signing
    request = approval_signing.ApprovalRequest(
        candidate_id=receipt["record_id"], rung="weights",
        payload_sha256=approved_digest)
    approver_id = approval_signing.verify(
        request,
        receipt["approval_signature"],
        [_server_approval_key_registry()[receipt["approval_key_id"]]],
    )
    if not approver_id or approver_id != record.approver_id:
        raise ValueError("adapter receipt signature does not verify cryptographically")


def _verify_live_deployment(pointer: dict) -> None:
    """Fail closed unless Ollama's live alias still matches its attestation."""
    _revalidate_model_improvement_pointer(pointer)
    serving = pointer.get("serving")
    if not isinstance(serving, dict):
        raise ValueError("adapter pointer has no serving binding")
    if serving.get("mode") == "manual":
        return
    if serving.get("mode") != "modelfile":
        raise ValueError("adapter pointer has an unsupported serving mode")
    improvement = pointer.get("model_improvement")
    if improvement is not None:
        qualification = _validated_model_improvement_binding(
            improvement,
        )["qualification"]
        if qualification is None:
            raise ValueError("model-improvement pointer has no qualification")
        if _ollama_engine_version() != qualification["engine_version"]:
            raise ValueError(
                "live Ollama engine version differs from qualification",
            )
    attestation = _validate_deployment_attestation(serving)
    model_name = serving.get("model_name")
    if not isinstance(model_name, str) or not model_name:
        raise ValueError("adapter pointer has no serving alias")
    observed = _ollama_model_digest(model_name)
    if observed != attestation["model_digest"]:
        raise ValueError("Ollama serving alias no longer matches its approved digest")


def _config_stamp() -> tuple:
    from . import config
    paths = [config.config_path(), config.dashboard_overrides_path()]
    try:
        tcfg = config.tenant_config_path()
    except Exception:  # pragma: no cover
        tcfg = None
    if tcfg is not None:
        paths.append(tcfg)
    return tuple(_stat_sig(p) for p in paths)


def _adapter_cfg() -> dict:
    """``config.get_adapter_rung()`` memoized by the config files' stat
    signature, so the (almost always disabled) hot path skips a full config
    interpolation on every LLM call."""
    from .config import get_adapter_rung
    try:
        stamp = _config_stamp()
    except Exception:  # pragma: no cover -- never block resolution
        return get_adapter_rung()
    hit = _CFG_CACHE.get("v")
    if hit is not None and hit[0] == stamp:
        return hit[1]
    cfg = get_adapter_rung()
    _CFG_CACHE["v"] = (stamp, cfg)
    return cfg


def _cached_active_pointer(root: Path, *, tenant_id: str | None = None) -> dict | None:
    """active.json read for the SERVING hot path, memoized by the pointer file's
    stat signature. Deliberately NOT used by activate()/rollback(), which must
    always see the live pointer."""
    tenant = _active_tenant_id() if tenant_id is None else _validated_tenant_id(tenant_id)
    store = AdapterStore(root, tenant_id=tenant)
    key = f"{root}:{tenant}"
    sig = (_stat_sig(root / POINTER_STATE_BASENAME),
           _stat_sig(root / ACTIVE_BASENAME))
    hit = _ACTIVE_CACHE.get(key)
    if hit is not None and hit[0] == sig:
        try:
            cached = hit[1]
            checked_at = time.monotonic()
            stamp = _serving_integrity_stamp(
                cached.get("serving") if cached is not None else None)
            receipt_stamp = _receipt_integrity_stamp(cached)
            serving_changed = len(hit) < 3 or hit[2] != stamp
            receipt_changed = len(hit) < 4 or hit[3] != receipt_stamp
            if serving_changed:
                # Metadata changed: do not trust the cached integrity verdict.
                # Rehash under the strict bounds before this request may route.
                if cached is not None:
                    _verify_serving_binding(cached.get("serving"))
            if receipt_changed:
                if cached is not None:
                    _verify_authoritative_pointer(
                        cached, artifact_identity=store.artifact_identity)
            last_live_check = hit[4] if len(hit) >= 5 else float("-inf")
            if (cached is not None
                    and (serving_changed or receipt_changed
                         or checked_at - last_live_check
                         >= SERVING_ALIAS_REVERIFY_SECONDS)):
                _verify_live_deployment(cached)
                last_live_check = checked_at
            _ACTIVE_CACHE[key] = (
                sig, cached, stamp, receipt_stamp, last_live_check)
            return cached
        except Exception:
            _ACTIVE_CACHE.pop(key, None)
            log.warning("cached adapter serving binding is no longer valid", exc_info=True)
            return None
    try:
        val = store.active()
        if val is not None:
            _verify_authoritative_pointer(
                val, artifact_identity=store.artifact_identity)
            _verify_live_deployment(val)
        stamp = _serving_integrity_stamp(
            val.get("serving") if val is not None else None)
        receipt_stamp = _receipt_integrity_stamp(val)
        _ACTIVE_CACHE[key] = (
            sig, val, stamp, receipt_stamp, time.monotonic())
        return val
    except Exception:
        _ACTIVE_CACHE.pop(key, None)
        log.warning("adapter pointer has no valid serving authority", exc_info=True)
        return None


def _store_root_from_cfg(cfg: dict, *, tenant_id: str | None = None) -> Path:
    tenant = _active_tenant_id() if tenant_id is None else _validated_tenant_id(tenant_id)
    store_dir = cfg.get("store_dir")
    if store_dir:
        root = Path(str(store_dir)).expanduser()
        if tenant:
            # Reuse paths.data_dir's canonical tenant encoding even when the
            # operator relocates adapter storage outside MAVERICK_HOME.
            from .paths import data_dir
            root = root / "tenants" / data_dir(tenant=tenant).name
        return root
    from .paths import data_dir
    return data_dir("adapters", tenant=tenant or None)


def default_store_root(*, tenant_id: str | None = None) -> Path:
    """Tenant-scoped configured store or authoritative ``data_dir('adapters')``.

    With no active tenant the legacy single-tenant path remains byte-for-byte
    ``~/.maverick/adapters``.
    """
    try:
        return _store_root_from_cfg(_adapter_cfg(), tenant_id=tenant_id)
    except Exception:  # pragma: no cover
        from .paths import data_dir
        tenant = _active_tenant_id() if tenant_id is None else _validated_tenant_id(tenant_id)
        return data_dir("adapters", tenant=tenant or None)


# --- serving seam (Ollama Modelfile ADAPTER) ---------------------------------------

def _model_id(spec: str) -> str:
    """Strip a known local provider prefix off a ``provider:model-id`` spec."""
    if ":" in spec:
        head, tail = spec.split(":", 1)
        if head.strip().lower() in {"ollama", "local"}:
            return tail
    return spec


def tuned_model_name(manifest: AdapterManifest) -> str:
    """Deterministic Ollama model name for a promoted adapter (tag-safe)."""
    _validate_manifest(manifest)
    raw_base = _model_id(manifest.base_model)
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", raw_base).strip("-._")[:48] or "model"
    identity = json.dumps({
        "tenant_id": manifest.tenant_id,
        "base_model": manifest.base_model,
        "adapter_id": manifest.adapter_id,
        "payload_sha256": manifest.payload_sha256,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"{base}-lw-{hashlib.sha256(identity).hexdigest()[:32]}"


def render_modelfile(manifest: AdapterManifest, adapter_dir: Path | str) -> str:
    """The Ollama Modelfile that binds base + adapter for serving. Written
    next to the payload by :func:`emit_serving_artifacts`. Governed promotion
    either stages and verifies it through the bounded Ollama management path or
    requires a custom provisioner to return an independently observed
    deployment attestation."""
    _validate_manifest(manifest)
    tenant = _validated_tenant_id(manifest.tenant_id)
    resolved = Path(adapter_dir).resolve()
    if any(ord(ch) < 32 for ch in str(resolved)):
        raise ValueError("adapter serving path contains control characters")
    tenant_line = f"# tenant {_tenant_tag(tenant)}\n" if tenant else ""
    return (f"# generated by maverick.adapter_rung for {manifest.adapter_id}\n"
            f"{tenant_line}"
            f"# dataset {manifest.dataset_sha256[:12]} · payload {manifest.payload_sha256[:12]}\n"
            f"FROM {_model_id(manifest.base_model)}\n"
            f"ADAPTER {resolved}\n")


def _serving_binding(manifest: AdapterManifest, adapter_dir: Path | str) -> dict:
    unresolved = Path(adapter_dir)
    if _is_unsafe_link(unresolved):
        raise ValueError("adapter payload root cannot be a link/reparse point")
    adapter_dir = unresolved.resolve()
    prov = _base_provider(manifest.base_model)
    common = {
        "tenant_id": _validated_tenant_id(manifest.tenant_id),
        "adapter_dir": str(adapter_dir),
        "payload_sha256": manifest.payload_sha256,
    }
    if prov not in _SERVING_PROVIDERS or not _model_id(manifest.base_model).strip():
        return {**common, "mode": "manual"}
    content = render_modelfile(manifest, adapter_dir).encode("utf-8")
    return {
        **common,
        "mode": "modelfile",
        "model_name": tuned_model_name(manifest),
        "modelfile": str(adapter_dir / SERVING_BASENAME),
        "modelfile_sha256": hashlib.sha256(content).hexdigest(),
    }


def _verify_serving_binding(binding: dict | None) -> None:
    """Prove a prepared serving artifact exists byte-identically."""
    if binding is None:  # legacy/dev low-level pointer
        return
    if not isinstance(binding, dict):
        raise ValueError("adapter serving binding is not an object")
    _validated_tenant_id(binding.get("tenant_id", ""))
    mode = binding.get("mode")
    adapter_dir = binding.get("adapter_dir")
    if not isinstance(adapter_dir, str) or not adapter_dir:
        raise ValueError("adapter serving binding has no payload directory")
    payload_root = Path(adapter_dir)
    payload_digest = binding.get("payload_sha256")
    if (_is_unsafe_link(payload_root) or not payload_root.is_dir()
            or not isinstance(payload_digest, str)
            or payload_digest_dir(payload_root) != payload_digest):
        raise ValueError("adapter serving payload digest mismatch")
    if mode == "manual":
        return
    if mode != "modelfile":
        raise ValueError("adapter serving binding has an unsupported mode")
    path_raw = binding.get("modelfile")
    digest = binding.get("modelfile_sha256")
    if not isinstance(path_raw, str) or not isinstance(digest, str):
        raise ValueError("adapter serving binding is incomplete")
    path = Path(path_raw)
    if _is_unsafe_link(path) or not path.is_file():
        raise ValueError("adapter serving Modelfile is missing or unsafe")
    if path.resolve().parent != payload_root.resolve():
        raise ValueError("adapter serving Modelfile escapes its payload directory")
    # Text mode normalizes the platform's newline convention, matching the
    # canonical LF bytes hashed when the binding was prepared.
    observed = hashlib.sha256(
        path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
    if observed != digest:
        raise ValueError("adapter serving Modelfile digest mismatch")


def emit_serving_artifacts(
    manifest: AdapterManifest, adapter_dir: Path | str, *,
    tenant_id: str | None = None, binding: dict | None = None,
) -> dict:
    """Write the Ollama ``Modelfile`` beside the payload and return the
    name/paths/command. For a base that is not an auto-served provider, or an
    empty model id, emit no Modelfile and return a note instead of a bogus
    command."""
    expected_tenant = _active_tenant_id() if tenant_id is None else _validated_tenant_id(tenant_id)
    _require_manifest_tenant(manifest, expected_tenant)
    adapter_dir = Path(adapter_dir)
    expected_binding = _serving_binding(manifest, adapter_dir)
    binding = dict(binding or expected_binding)
    if binding != expected_binding:
        raise ValueError("adapter serving binding does not match the manifest")
    if _validated_tenant_id(binding.get("tenant_id", "")) != expected_tenant:
        raise ValueError("adapter serving binding belongs to another tenant")
    prov = _base_provider(manifest.base_model)
    if prov not in _SERVING_PROVIDERS:
        return {"model_name": None, "create_command": None,
                "note": f"base provider {prov or '(none)'!r} is not auto-served; "
                        "wire the promoted adapter into your serving stack manually",
                "adapter_dir": str(adapter_dir.resolve()),
                "tenant_id": expected_tenant, "binding": binding}
    if not _model_id(manifest.base_model).strip():
        return {"model_name": None, "create_command": None,
                "note": "base_model has no model id (e.g. 'ollama:'); cannot render a Modelfile",
                "adapter_dir": str(adapter_dir.resolve()),
                "tenant_id": expected_tenant, "binding": binding}
    modelfile = adapter_dir / SERVING_BASENAME  # .txt: stays inside the hygiene allowlist
    from .file_lock import atomic_write_text
    atomic_write_text(modelfile, render_modelfile(manifest, adapter_dir), mode=0o600)
    _verify_serving_binding(binding)
    name = tuned_model_name(manifest)
    argv = ["ollama", "create", name, "-f", str(modelfile)]
    return {
        "model_name": name,
        "modelfile": str(modelfile),
        "create_argv": argv,
        # Compatibility/display only. Callers executing the operation must use
        # create_argv so no shell parses a model or path as syntax.
        "create_command": subprocess.list2cmdline(argv),
        "tenant_id": expected_tenant,
        "binding": binding,
    }


def _validate_deployment_attestation(
    binding: dict,
    *,
    required_runtime: Mapping[str, Any] | None = None,
) -> dict:
    """Validate proof that the deterministic local model was installed."""
    deployment = binding.get("deployment")
    if not isinstance(deployment, dict) or deployment.get("version") != 1:
        raise ValueError("adapter serving model has no deployment attestation")
    attestation = dict(deployment)
    if attestation.get("provider") != "ollama" or attestation.get("verified") is not True:
        raise ValueError("adapter serving model was not independently verified")
    if attestation.get("model_name") != binding.get("model_name"):
        raise ValueError("adapter serving attestation names another model")
    if attestation.get("source_modelfile_sha256") != binding.get("modelfile_sha256"):
        raise ValueError("adapter serving attestation binds another Modelfile")
    if required_runtime is not None:
        actual_runtime = attestation.get("model_improvement_runtime")
        expected = dict(required_runtime)
        if actual_runtime != expected:
            raise ValueError(
                "adapter serving attestation binds another qualified runtime",
            )
        runtime_digest = expected.get("runtime_attestation_sha256")
        if (
            not isinstance(runtime_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", runtime_digest)
            or attestation.get("model_improvement_runtime_sha256")
            != runtime_digest
        ):
            raise ValueError("adapter serving runtime digest is inconsistent")
    digest = attestation.get("model_digest")
    if (not isinstance(digest, str) or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)):
        raise ValueError("adapter serving attestation has an invalid model digest")
    verified_at = attestation.get("verified_at")
    if (not isinstance(verified_at, (int, float)) or isinstance(verified_at, bool)
            or not math.isfinite(float(verified_at)) or float(verified_at) < 0):
        raise ValueError("adapter serving attestation has an invalid timestamp")
    return attestation


def _ollama_api_origin() -> str:
    """Return a validated HTTP(S) origin for Ollama's local management API."""
    from urllib.parse import urlsplit, urlunsplit
    raw = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").strip()
    if raw.startswith(":"):
        raw = "127.0.0.1" + raw
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlsplit(raw)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"}):
        raise ValueError("OLLAMA_HOST must be an HTTP(S) origin without credentials or a path")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")


def _ollama_engine_version() -> str:
    """Read Ollama's bounded live engine version from its management API."""
    from urllib.request import Request, urlopen

    request = Request(f"{_ollama_api_origin()}/api/version", method="GET")
    with urlopen(request, timeout=OLLAMA_API_TIMEOUT_SECONDS) as response:  # noqa: S310
        raw = response.read(4097)
    if len(raw) > 4096:
        raise RuntimeError("Ollama version response exceeded the response limit")
    payload = json.loads(raw.decode("utf-8"))
    version = payload.get("version") if isinstance(payload, dict) else None
    if (
        not isinstance(version, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}", version)
    ):
        raise RuntimeError("Ollama returned an invalid engine version")
    return version


def _ollama_model_digest(model_name: str) -> str | None:
    """Read Ollama's full manifest digest for one installed model."""
    from urllib.request import Request, urlopen
    request = Request(f"{_ollama_api_origin()}/api/tags", method="GET")
    with urlopen(request, timeout=OLLAMA_API_TIMEOUT_SECONDS) as response:  # noqa: S310
        raw = response.read(OLLAMA_API_RESPONSE_BYTES + 1)
    if len(raw) > OLLAMA_API_RESPONSE_BYTES:
        raise RuntimeError("Ollama model inventory exceeded the response limit")
    payload = json.loads(raw.decode("utf-8"))
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        raise RuntimeError("Ollama returned an invalid model inventory")
    aliases = {model_name, f"{model_name}:latest"}
    for item in models:
        if not isinstance(item, dict):
            continue
        if item.get("name") not in aliases and item.get("model") not in aliases:
            continue
        digest = item.get("digest")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)):
            raise RuntimeError("Ollama returned an invalid model digest")
        return digest
    return None


def _ollama_copy_model(source: str, destination: str) -> None:
    """Copy a verification build to its deterministic name via Ollama's API."""
    from urllib.request import Request, urlopen
    body = json.dumps({"source": source, "destination": destination}).encode("utf-8")
    request = Request(
        f"{_ollama_api_origin()}/api/copy", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=OLLAMA_API_TIMEOUT_SECONDS) as response:  # noqa: S310
        raw = response.read(OLLAMA_API_RESPONSE_BYTES + 1)
    if len(raw) > OLLAMA_API_RESPONSE_BYTES:
        raise RuntimeError("Ollama copy response exceeded the response limit")


def _run_ollama(argv: list[str], *, required: bool = True) -> bool:
    """Execute a bounded, non-shell Ollama management operation."""
    try:
        result = subprocess.run(  # noqa: S603 - fixed executable/argv, never a shell
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False,
            timeout=OLLAMA_INSTALL_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if required:
            raise RuntimeError(f"Ollama operation failed: {argv[1]}") from exc
        return False
    if result.returncode != 0:
        if required:
            raise RuntimeError(f"Ollama operation failed: {argv[1]}")
        return False
    return True


def _ollama_stage_and_attest(binding: dict) -> tuple[dict, dict]:
    """Build and attest a nonce alias without touching the production alias."""
    _verify_serving_binding(binding)
    name = binding.get("model_name")
    modelfile = binding.get("modelfile")
    if not isinstance(name, str) or not isinstance(modelfile, str):
        raise ValueError("adapter serving binding cannot be installed")
    temporary = f"{name}-verify-{uuid.uuid4().hex[:12]}"
    try:
        _run_ollama(["ollama", "create", temporary, "-f", modelfile])
        expected = _ollama_model_digest(temporary)
        if expected is None:
            raise RuntimeError("Ollama did not publish the verification model")
        attestation = {
            "version": 1,
            "provider": "ollama",
            "verified": True,
            "model_name": name,
            "model_digest": expected,
            "source_modelfile_sha256": binding["modelfile_sha256"],
            "verified_at": time.time(),
        }
        return attestation, {
            "temporary_model_name": temporary,
            "model_digest": expected,
        }
    except BaseException:
        _run_ollama(["ollama", "rm", temporary], required=False)
        raise


def _ollama_activate_staged(binding: dict, stage: dict) -> None:
    """Publish a previously attested nonce build to the final Ollama alias."""
    _verify_serving_binding(binding)
    name = binding.get("model_name")
    temporary = stage.get("temporary_model_name")
    expected = stage.get("model_digest")
    if (not isinstance(name, str) or not isinstance(temporary, str)
            or not isinstance(expected, str)):
        raise ValueError("adapter serving stage is invalid")
    if _ollama_model_digest(temporary) != expected:
        raise RuntimeError("Ollama verification model changed before activation")
    current = _ollama_model_digest(name)
    if current != expected:
        if current is not None:
            _run_ollama(["ollama", "rm", name])
        _ollama_copy_model(temporary, name)
    observed = _ollama_model_digest(name)
    if observed != expected:
        raise RuntimeError("Ollama final model digest does not match verification build")


def _ollama_cleanup_stage(stage: dict) -> None:
    temporary = stage.get("temporary_model_name")
    if isinstance(temporary, str) and temporary:
        _run_ollama(["ollama", "rm", temporary], required=False)


def _ollama_install_and_verify(binding: dict) -> dict:
    """Compatibility helper: stage, publish, verify, and clean one model."""
    attestation, stage = _ollama_stage_and_attest(binding)
    try:
        _ollama_activate_staged({**binding, "deployment": attestation}, stage)
        return attestation
    finally:
        _ollama_cleanup_stage(stage)


@dataclass
class _ServingProvision:
    binding: dict
    authoritative: bool
    activate: Callable[[], None] | None = field(default=None, repr=False)
    cleanup: Callable[[], None] | None = field(default=None, repr=False)
    verify_live: bool = False


def _provision_serving_model(
    binding: dict, *, provisioner: Callable[[dict], dict] | None,
    allow_uninstalled_dev: bool,
    required_runtime: Mapping[str, Any] | None = None,
) -> _ServingProvision:
    """Stage serving evidence and defer production alias mutation until approval.

    A custom provisioner is an integration seam and must likewise return an
    attestation for non-routable staged state; the built-in Ollama path enforces
    that property structurally with a nonce alias.
    """
    if binding.get("mode") == "manual":
        return _ServingProvision(dict(binding), True)
    if allow_uninstalled_dev and provisioner is None:
        # Explicit development compatibility: the governed decision may still
        # be exercised, but this pointer is marked unbound and can never reroute
        # a provider request.
        return _ServingProvision(dict(binding), False)
    if provisioner is not None:
        request = dict(binding)
        if required_runtime is not None:
            request["required_model_improvement_runtime"] = dict(
                required_runtime,
            )
        attestation = provisioner(request)
        enriched = {**binding, "deployment": dict(attestation)}
        _validate_deployment_attestation(
            enriched,
            required_runtime=required_runtime,
        )
        return _ServingProvision(enriched, True)
    if required_runtime is not None:
        raise ValueError(
            "model-improvement Ollama routing requires a provisioner that "
            "independently attests engine, version, context, concurrency, "
            "hardware, lock, and deployment-manifest identity",
        )
    attestation, stage = _ollama_stage_and_attest(binding)
    enriched = {**binding, "deployment": dict(attestation)}
    _validate_deployment_attestation(enriched)
    return _ServingProvision(
        enriched, True,
        activate=lambda: _ollama_activate_staged(enriched, stage),
        cleanup=lambda: _ollama_cleanup_stage(stage),
        verify_live=True,
    )


def effective_wire_model(provider: str, model_id: str) -> str:
    """The wire-level model id for a LOCAL provider request: the promoted tuned
    name when the active adapter was promoted for exactly this base, else the
    id unchanged.

    Called by the provider client at request-BUILD time (the last moment before
    the wire), NOT during spec parsing -- so admin allow-lists, pricing,
    metrics, and provider-health all keep the stable base model id (bounded
    label cardinality; the allow-list judges the base the operator actually
    allow-listed, and the adapter riding on it carries its own Ed25519-signed
    weights-rung approval). Fail-open on any doubt: serving must never break
    because a pointer is stale, so every exception returns the id unchanged."""
    try:
        if provider.strip().lower() not in _SERVING_PROVIDERS or not model_id.strip():
            return model_id
        cfg = _adapter_cfg()
        if not cfg.get("enable"):
            return model_id
        tenant = _active_tenant_id()
        active = _cached_active_pointer(
            _store_root_from_cfg(cfg, tenant_id=tenant), tenant_id=tenant)
        if not active:
            return model_id
        active_base = str(active.get("base_model", ""))
        # Match on the model-id half (ollama/local are aliases of one client)
        # and never honor a pointer whose base is not an auto-served provider.
        if (_base_provider(active_base) not in _SERVING_PROVIDERS
                or _model_id(active_base) != model_id):
            return model_id
        adapter_id = str(active.get("adapter_id", ""))
        if not adapter_id:
            return model_id
        manifest = AdapterManifest(adapter_id=adapter_id, base_model=active_base,
                                   trainer="", dataset_sha256="", examples=0,
                                   payload_sha256=str(active.get("payload_sha256", "")),
                                   tenant_id=tenant)
        tuned = tuned_model_name(manifest)
        if not tuned or tuned.startswith("-lw-"):  # empty/degenerate base model id
            return model_id
        return tuned
    except Exception:  # pragma: no cover -- serving must not depend on the rung
        log.debug("effective_wire_model fail-open", exc_info=True)
        return model_id


def effective_model_spec(spec: str) -> str:
    """Resolution helper for display/ops surfaces (dashboard, CLI `doctor`):
    the full spec a base spec currently serves as, via
    :func:`effective_wire_model`. NOT wired into ``llm._parse_spec`` -- spec
    parsing stays pure; the wire-level rewrite happens inside the Ollama
    provider client."""
    provider = _base_provider(spec)
    if provider not in _SERVING_PROVIDERS:
        return spec
    wire = effective_wire_model(provider, _model_id(spec))
    return spec if wire == _model_id(spec) else f"ollama:{wire}"


# --- the governed decision ----------------------------------------------------------

@dataclass
class AdapterUpliftResult:
    """Verdict on one proposed adapter promotion (mirrors ``UpliftResult``)."""

    hygiene_ok: bool = False
    fitness: AdapterEvalResult = field(default_factory=AdapterEvalResult)
    promoted: bool = False
    approver_id: str | None = None
    candidate_id: str = ""
    pointer: dict | None = None
    serving: dict | None = None
    reason: str = ""


def _require_durable_adapter_ledger(controller):
    from .self_improvement import PromotionLedgerError
    ledger = getattr(controller, "ledger", None)
    if ledger is None:
        raise PromotionLedgerError("adapter promotion requires a durable ledger")
    if getattr(ledger, "path", None) is None and not bool(
        getattr(ledger, "durable", False)
    ):
        raise PromotionLedgerError("in-memory promotion ledgers cannot deploy adapters")
    return ledger


def _promotion_receipt_binding(
    candidate, ledger, *, approval_pubkey: str, artifact_identity: str,
) -> dict:
    path = getattr(ledger, "path", None)
    if path is None:
        raise ValueError(
            "adapter serving authority requires a filesystem-backed durable ledger")
    signature = getattr(candidate, "approval_signature", None)
    digest = getattr(candidate, "payload_sha256", None)
    approved_payload = getattr(candidate, "payload", None)
    if not signature or not digest or not isinstance(approved_payload, str):
        raise ValueError("adapter serving authority requires payload-bound approval")
    if hashlib.sha256(approved_payload.encode("utf-8")).hexdigest() != digest:
        raise ValueError("adapter serving authority payload digest is inconsistent")
    public_key = _validated_approval_public_keys([approval_pubkey])[0]
    from . import approval_signing

    approval_key_id = approval_signing.key_id(public_key)
    if _server_approval_key_registry().get(approval_key_id) != public_key:
        raise ValueError(
            "adapter serving authority requires a server-trusted approver key",
        )
    return {
        "version": 3,
        "tenant_id": _active_tenant_id(),
        "record_id": str(candidate.id),
        "ledger_path": str(Path(path).expanduser().resolve()),
        "payload_sha256": str(digest),
        "approval_signature": str(signature),
        "approval_key_id": approval_key_id,
        "approved_payload": approved_payload,
        "artifact_identity": artifact_identity,
    }


def _recover_adapter_rollback_locked(store: AdapterStore, ledger) -> dict | None:
    """Resolve the tenant pointer's durable rollback intent, if present."""
    from .self_improvement import ArtifactRevision, PromotionLedgerError
    state = store._read_state_locked(verify_serving=True)
    intent = state.pending_rollback
    if intent is None:
        return None
    before = ArtifactRevision(**intent["before"])
    after = ArtifactRevision(**intent["after"])
    observed = store._revision(state)
    try:
        record = ledger.get(intent["record_id"])
    except Exception as exc:
        raise PromotionLedgerError("adapter rollback authority is unavailable") from exc
    if record is None:
        raise PromotionLedgerError("adapter rollback record disappeared")
    record_tenant = _validated_tenant_id(record.provenance.get("tenant_id", ""))
    if record_tenant != store.tenant_id:
        raise PromotionLedgerError("adapter rollback receipt belongs to another tenant")

    if observed == after:
        if not record.rolled_back:
            try:
                ledger.mark_rolled_back(intent["record_id"], at=time.time())
                record = ledger.get(intent["record_id"])
            except Exception as exc:
                raise PromotionLedgerError(
                    "adapter rollback COMMIT is in doubt; recovery required"
                ) from exc
        if record is None or not record.rolled_back:
            raise PromotionLedgerError(
                "adapter rollback COMMIT is in doubt; recovery required")
        store._write_state_locked(_PointerState(
            active=state.active, previous=state.previous, pending_rollback=None))
        return {"state": "committed", "record_id": intent["record_id"]}
    if observed == before:
        if record.rolled_back:
            raise PromotionLedgerError(
                "rollback receipt is committed but the before pointer remains live")
        store._write_state_locked(_PointerState(
            active=state.active, previous=state.previous, pending_rollback=None))
        return {"state": "aborted", "record_id": intent["record_id"]}
    raise PromotionLedgerError(
        "adapter rollback pointer matches neither prepared revision")


def recover_adapter_promotions(controller, *, store: AdapterStore | None = None) -> list:
    """Reconcile crash-left adapter PREPAREs before accepting another write.

    Exact-after (including the serving artifact digest) commits, exact-before
    aborts, and an ambiguous state remains durably in doubt and blocks the
    artifact identity through the shared promotion ledger.
    """
    from .self_improvement import PromotionLedgerError
    st = store or AdapterStore()
    if st.tenant_id != _active_tenant_id():
        raise PromotionLedgerError(
            "adapter recovery store tenant does not match active context")
    ledger = _require_durable_adapter_ledger(controller)
    with st.transaction_locked():
        _recover_adapter_rollback_locked(st, ledger)
        recovered = controller.recover_promotions(
            st.inspect_revision, artifact_identity=st.artifact_identity)
    if any(getattr(tx, "in_doubt", False) for tx in recovered):
        raise PromotionLedgerError("unresolved adapter promotion blocks activation")
    return recovered


def _abort_adapter_prepare(controller, preparation, store: AdapterStore, *, reason: str) -> bool:
    """ABORT only when strict inspection proves exact-before still serves."""
    try:
        transaction = preparation.transaction
        if transaction is None:
            return False
        observed = store.inspect_revision(transaction.before.identity)
        if observed != transaction.before:
            return False
        controller.abort_prepared(preparation, artifact=observed, reason=reason)
        current = controller.ledger.transaction(transaction.id)
        return current is not None and current.state == "aborted"
    except Exception:
        log.warning("adapter promotion abort is in doubt", exc_info=True)
        return False


def _finalize_adapter_approval(
    cand, *, manifest: AdapterManifest, serving_binding: dict,
    store: AdapterStore, approve: Callable[[Any], str | None] | None,
    approval_signature: str | None, approval_public_keys: tuple[str, ...],
    ledger_path: Path | str,
    model_improvement: dict[str, Any] | None,
):
    proposed_pointer = {
        "authority": "governed-v1",
        "tenant_id": store.tenant_id,
        "promotion_record_id": cand.id,
        "adapter_id": manifest.adapter_id,
        "base_model": manifest.base_model,
        "dataset_sha256": manifest.dataset_sha256,
        "payload_sha256": manifest.payload_sha256,
        "serving": serving_binding,
    }
    if model_improvement is not None:
        proposed_pointer["model_improvement"] = (
            _validated_model_improvement_binding(model_improvement)
        )
    approved_payload = _authority_payload(
        proposed_pointer, artifact_identity=store.artifact_identity,
        ledger_path=ledger_path)
    cand = replace(
        cand, payload=approved_payload,
        payload_sha256=hashlib.sha256(
            approved_payload.encode("utf-8")).hexdigest())
    cand = _attach_adapter_approval(
        cand, approve=approve, approval_signature=approval_signature)
    approval_pubkey, approver_id = _approval_key_for_candidate(
        cand, approval_public_keys)
    return cand, approval_pubkey, approver_id


def _recover_adapter_state_locked(store: AdapterStore, controller, candidate_id: str):
    _recover_adapter_rollback_locked(store, controller.ledger)
    recovered = controller.recover_promotions(
        store.inspect_revision, artifact_identity=store.artifact_identity)
    if any(getattr(tx, "in_doubt", False) for tx in recovered):
        raise RuntimeError("unresolved adapter promotion blocks activation")
    existing = controller.ledger.get(candidate_id)
    current = store._read_state_locked(verify_serving=True).active
    if current is not None and current.get("authority") == "governed-v1":
        _verify_authoritative_pointer(
            current, artifact_identity=store.artifact_identity)
    return existing, current


def _pointer_matches_manifest(
    pointer: dict | None, manifest: AdapterManifest, candidate_id: str,
) -> bool:
    return bool(
        pointer is not None
        and pointer.get("promotion_record_id") == candidate_id
        and pointer.get("adapter_id") == manifest.adapter_id
        and pointer.get("base_model") == manifest.base_model
        and pointer.get("dataset_sha256") == manifest.dataset_sha256
        and pointer.get("payload_sha256") == manifest.payload_sha256)


def _apply_prepared_adapter(
    out: AdapterUpliftResult, *, plan: AdapterActivationPlan,
    preparation, provision: _ServingProvision, controller, store: AdapterStore,
) -> AdapterUpliftResult:
    authorization = controller.authorize_prepared(
        preparation,
        artifact=plan.before,
    )
    if not authorization.ok:
        out.reason = (
            "gate refused before adapter activation: "
            f"{authorization.blocking_reason}"
        )
        return out
    try:
        if provision.activate is not None:
            provision.activate()
        if provision.verify_live:
            _verify_live_deployment(plan.pointer)
    except Exception as exc:
        closed = _abort_adapter_prepare(
            controller, preparation, store,
            reason="adapter serving alias activation failed")
        suffix = "transaction aborted" if closed else "recovery required"
        out.reason = f"adapter serving activation failed ({suffix}): {exc}"
        return out

    try:
        observed = store._apply_activation_locked(plan)
        out.pointer = dict(plan.pointer)
    except Exception as exc:
        closed = _abort_adapter_prepare(
            controller, preparation, store, reason="adapter activation CAS failed")
        suffix = "transaction aborted" if closed else "recovery required"
        out.reason = f"adapter activation failed ({suffix}): {exc}"
        return out

    if provision.verify_live:
        try:
            _verify_live_deployment(plan.pointer)
        except Exception as exc:
            out.reason = (
                "adapter activation is live with a durable PREPARE; "
                f"serving re-attestation failed and recovery is required: {exc}")
            return out

    verdict = controller.commit_prepared(preparation, artifact=observed)
    try:
        transaction = controller.ledger.transaction(preparation.transaction_id)
    except Exception:
        transaction = None
    out.promoted = bool(
        verdict.ok and transaction is not None and transaction.state == "committed")
    if not out.promoted:
        out.reason = (
            "adapter activation is live with a durable PREPARE; "
            "COMMIT is in doubt and recovery is required")
    return out


def _execute_locked_adapter_transaction(
    out: AdapterUpliftResult, *, cand, manifest: AdapterManifest,
    serving_binding: dict, receipt: dict | None, provision: _ServingProvision,
    controller, store: AdapterStore, ledger_path: Path | str,
    model_improvement: dict[str, Any] | None,
) -> AdapterUpliftResult:
    with store.transaction_locked():
        try:
            existing, current = _recover_adapter_state_locked(
                store, controller, cand.id)
        except Exception as exc:
            out.reason = f"adapter promotion recovery failed: {exc}"
            return out
        if existing is not None:
            if (_pointer_matches_manifest(current, manifest, cand.id)
                    and not existing.rolled_back
                    and existing.payload_sha256 == cand.payload_sha256
                    and existing.provenance == cand.provenance):
                out.promoted = True
                out.approver_id = existing.approver_id
                out.pointer = current
                out.reason = "PROMOTED: recovered committed adapter activation"
                return out
            out.reason = "promotion candidate id already belongs to another adapter state"
            return out

        try:
            plan = store._plan_activation_locked(
                manifest, record_id=cand.id, activated_at=controller.now(),
                serving=serving_binding, receipt=receipt,
                model_improvement=model_improvement)
            if (_authority_payload(
                    plan.pointer, artifact_identity=store.artifact_identity,
                    ledger_path=ledger_path)
                    != cand.payload):
                raise ValueError("activation plan differs from the approved payload")
            preparation = controller.prepare_promotion(
                cand, before=plan.before, after=plan.after)
        except Exception as exc:
            out.reason = f"adapter promotion PREPARE failed: {exc}"
            return out
        out.approver_id = preparation.verdict.approver_id
        if not preparation.ok:
            out.reason = f"gate refused: {preparation.blocking_reason}"
            return out
        if preparation.committed:
            if store.inspect_revision(store.artifact_identity) != plan.after:
                out.reason = "committed adapter receipt does not match serving state"
                return out
            out.promoted = True
            out.pointer = plan.pointer
            out.reason = "PROMOTED: idempotent committed adapter activation"
            return out
        return _apply_prepared_adapter(
            out, plan=plan, preparation=preparation, provision=provision,
            controller=controller, store=store)


def _execute_adapter_transaction(
    out: AdapterUpliftResult, *, cand, manifest: AdapterManifest,
    adapter_dir: Path, controller, store: AdapterStore,
    serving_provisioner: Callable[[dict], dict] | None,
    approve: Callable[[Any], str | None] | None,
    approval_signature: str | None,
    approval_public_keys: tuple[str, ...],
    allow_uninstalled_dev: bool,
    model_improvement: dict[str, Any] | None,
) -> AdapterUpliftResult:
    """Approve exact staged state, then PREPARE/effect/inspect/COMMIT."""
    provision: _ServingProvision | None = None
    try:
        _require_durable_adapter_ledger(controller)
        serving_binding = _serving_binding(manifest, adapter_dir)
        out.serving = emit_serving_artifacts(
            manifest, adapter_dir, tenant_id=store.tenant_id,
            binding=serving_binding)
        runtime_requirement = None
        if model_improvement is not None:
            qualification = model_improvement.get("qualification")
            if not isinstance(qualification, Mapping):
                raise ValueError(
                    "model-improvement serving requires a qualification binding",
                )
            if (
                serving_binding.get("mode") == "modelfile"
                and str(qualification.get("engine") or "").lower() != "ollama"
            ):
                raise ValueError(
                    "Ollama serving requires an Ollama-qualified runtime",
                )
            runtime_requirement = _model_improvement_runtime_requirement(
                model_improvement,
            )
    except Exception as exc:
        out.reason = f"adapter serving preparation failed: {exc}"
        return out
    try:
        from .self_improvement import enabled as self_improvement_enabled
        if not self_improvement_enabled():
            out.reason = "gate refused: self-improvement disabled"
            return out
        provision = _provision_serving_model(
            serving_binding, provisioner=serving_provisioner,
            allow_uninstalled_dev=allow_uninstalled_dev,
            required_runtime=runtime_requirement)
        serving_binding = provision.binding
        out.serving["binding"] = serving_binding
        if serving_binding.get("deployment") is not None:
            out.serving["deployment"] = serving_binding["deployment"]
    except Exception as exc:
        out.reason = f"adapter serving installation failed: {exc}"
        return out

    try:
        try:
            ledger_path = getattr(controller.ledger, "path", None)
            if ledger_path is None:
                raise ValueError(
                    "adapter exact approval requires a filesystem-backed ledger")
            cand, approval_pubkey, cryptographic_approver = \
                _finalize_adapter_approval(
                    cand, manifest=manifest, serving_binding=serving_binding,
                    store=store, approve=approve,
                    approval_signature=approval_signature,
                    approval_public_keys=approval_public_keys,
                    ledger_path=ledger_path,
                    model_improvement=model_improvement)
        except Exception as exc:
            out.reason = f"external adapter approval failed: {exc}"
            return out
        preflight = controller.evaluate(cand)
        out.approver_id = preflight.approver_id
        if not preflight.ok:
            out.reason = f"gate refused: {preflight.blocking_reason}"
            return out
        if preflight.approver_id != cryptographic_approver:
            out.reason = "gate refused: scoped verifier disagrees with trusted approval key"
            return out
        receipt = (
            _promotion_receipt_binding(
                cand, controller.ledger, approval_pubkey=approval_pubkey,
                artifact_identity=store.artifact_identity)
            if provision.authoritative else None)
        return _execute_locked_adapter_transaction(
            out, cand=cand, manifest=manifest, serving_binding=serving_binding,
            receipt=receipt, provision=provision,
            controller=controller, store=store, ledger_path=ledger_path,
            model_improvement=model_improvement)
    finally:
        if provision is not None and provision.cleanup is not None:
            try:
                provision.cleanup()
            except Exception:
                log.warning("adapter serving staging cleanup failed", exc_info=True)


def _unsafe_dev_approval_callbacks(keys_dir: Path | str):
    """Legacy local signer, available only through the explicit unsafe switch."""
    from . import approval_signing as asig
    directory = Path(keys_dir)
    private_path = directory / "operator.priv.hex"
    if not private_path.is_file():
        raise ValueError(f"no unsafe development signing key at {private_path}")
    public_keys = asig._keys_from_dir(str(directory))  # noqa: SLF001 - scoped legacy seam
    if not public_keys:
        raise ValueError("unsafe development approval directory has no public key")
    private_hex = private_path.read_text(encoding="utf-8").strip()

    def approve(request):
        return asig.sign_request(request, private_hex)

    def verify(candidate):
        signature = getattr(candidate, "approval_signature", None)
        if not signature:
            return None
        return asig.verify(
            asig.ApprovalRequest.for_candidate(candidate), str(signature), public_keys)

    return approve, verify, _validated_approval_public_keys(public_keys)


def _adapter_min_improvement_from_config() -> float:
    """Return the trusted adapter promotion margin or refuse the policy."""
    from .config import config_source_errors, load_config

    # ``load_config`` is intentionally fail-soft for ordinary model selection,
    # so a mutation boundary must consult its trust side-channel explicitly.
    snapshot = load_config()
    if config_source_errors():
        raise ValueError("adapter promotion policy source is invalid")
    raw_section = snapshot.get("self_improvement", {})
    if not isinstance(raw_section, dict):
        raise ValueError("adapter promotion policy is invalid")
    raw_margin = raw_section.get("min_improvement", 0.0)
    if (
        not isinstance(raw_margin, (int, float))
        or isinstance(raw_margin, bool)
        or not math.isfinite(float(raw_margin))
        or not 0.0 <= float(raw_margin) <= 1.0
    ):
        raise ValueError("adapter promotion min_improvement is invalid")
    return float(raw_margin)


def _model_improvement_policy() -> dict[str, Any]:
    """Return trusted model-improvement policy or refuse a malformed source.

    Ordinary config reads are intentionally fail-soft.  Adapter activation is
    a privileged mutation boundary, so it must not reinterpret an unreadable
    or structurally invalid policy as "feature disabled".
    """
    from .config import get_model_improvement_mutation_policy

    return dict(get_model_improvement_mutation_policy())


def _model_improvement_policy_digest(policy: Mapping[str, Any]) -> str:
    """Content address the strict effective policy bound to a live pointer."""
    try:
        encoded = json.dumps(
            dict(policy),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("model-improvement policy is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _model_improvement_receipt_required() -> bool:
    policy = _model_improvement_policy()
    if policy["enable"] and policy["require_signed_receipt"] is not True:
        raise ValueError(
            "enabled model improvement requires signed training receipts",
        )
    return bool(policy["enable"])


def _model_improvement_enabled() -> bool:
    return bool(_model_improvement_policy()["enable"])


def _verified_training_receipt_binding(
    *,
    receipt_id: str | None,
    manifest: AdapterManifest,
    adapter_sha256: str,
    model_improvement_policy: Mapping[str, Any] | None = None,
) -> dict[str, str] | None:
    """Verify and bind the exact private training run to a staged adapter.

    The caller supplies only a receipt identifier. The receipt itself is
    recovered from the active tenant's private store, and both trust roots come
    from protected server-side registries. The returned provenance is
    content-free.
    """
    receipt_required = (
        _model_improvement_receipt_required()
        if model_improvement_policy is None
        else bool(model_improvement_policy.get("enable"))
    )
    if (
        receipt_required
        and model_improvement_policy is not None
        and model_improvement_policy.get("require_signed_receipt") is not True
    ):
        raise ValueError(
            "enabled model improvement requires signed training receipts",
        )
    if not receipt_required:
        return None
    if not isinstance(receipt_id, str) or not receipt_id.strip():
        raise ValueError(
            "model-improvement adapter promotion requires a training receipt id"
        )
    if receipt_id != receipt_id.strip() or len(receipt_id) > 128:
        raise ValueError("training receipt id is invalid")

    from .training import receipts as training_receipts

    tenant_id = _active_tenant_id()
    if not tenant_id:
        raise ValueError(
            "model-improvement training receipts require an explicit tenant"
        )
    trusted_receipt_pubkeys, trusted_approver_pubkeys = (
        training_receipts.server_training_trust_registries()
    )
    receipt = training_receipts.read_verified_training_receipt(
        receipt_id,
        trusted_receipt_pubkeys=trusted_receipt_pubkeys,
        trusted_approver_pubkeys=trusted_approver_pubkeys,
        expected_tenant_id=tenant_id,
    )

    evidence = receipt.get("evidence")
    if not isinstance(evidence, Mapping):
        raise ValueError("verified training receipt has no run evidence")
    adapter = evidence.get("adapter")
    base_model = evidence.get("base_model")
    training = evidence.get("training")
    evaluation = evidence.get("evaluation")
    if (
        not isinstance(adapter, Mapping)
        or not isinstance(base_model, Mapping)
        or not isinstance(training, Mapping)
        or not isinstance(evaluation, Mapping)
    ):
        raise ValueError("verified training receipt has incomplete artifact evidence")
    if adapter.get("artifact_sha256") != adapter_sha256:
        raise ValueError("training receipt covers different adapter bytes")
    if evidence.get("dataset_sha256") != manifest.dataset_sha256:
        raise ValueError("training receipt covers a different training dataset")
    if base_model.get("model_id") != _model_id(manifest.base_model):
        raise ValueError("training receipt covers a different base model")
    if adapter.get("adapter_id") != manifest.adapter_id:
        raise ValueError("training receipt covers a different adapter identity")
    if training.get("backend") != manifest.trainer:
        raise ValueError("training receipt covers a different trainer")

    commitment = training_receipts.public_transparency_commitment(
        receipt,
        trusted_receipt_pubkeys=trusted_receipt_pubkeys,
        trusted_approver_pubkeys=trusted_approver_pubkeys,
        expected_tenant_id=tenant_id,
    )
    return {
        "receipt_payload_sha256": str(commitment["receipt_payload_sha256"]),
        "event_hash": str(commitment["event_hash"]),
        "key_id": str(commitment["key_id"]),
        "approval_subject_sha256": str(
            commitment["approval_subject_sha256"]
        ),
        "training_run_id": str(evidence["run_id"]),
        "training_completed_at": str(evidence["completed_at"]),
        "receipt_issued_at": str(receipt["issued_at"]),
        "dataset_sha256": str(evidence["dataset_sha256"]),
        "environment_sha256": str(evidence["environment_sha256"]),
        "environment_id": str(evidence["environment_id"]),
        "adapter_id": str(adapter["adapter_id"]),
        "adapter_sha256": str(adapter["artifact_sha256"]),
        "training_backend": str(training["backend"]),
        "base_model_id": str(base_model["model_id"]),
        "base_model_revision": str(base_model["revision"]),
        "base_model_license_id": str(base_model["license_id"]),
        "base_model_license_evidence_sha256": str(
            base_model["license_evidence_sha256"],
        ),
        "base_model_artifact_sha256": str(base_model["artifact_sha256"]),
        "base_model_artifact_manifest_sha256": str(
            base_model["artifact_manifest_sha256"],
        ),
        "base_model_tokenizer_sha256": str(base_model["tokenizer_sha256"]),
        "base_model_artifact_format": str(base_model["artifact_format"]),
        "adapter_artifact_format": str(adapter["artifact_format"]),
        "adapter_checkpoint_sha256": str(adapter["checkpoint_sha256"]),
        "adapter_runtime_compatibility_sha256": str(
            adapter["runtime_compatibility_sha256"],
        ),
        "evaluation_protocol_sha256": str(
            evaluation["protocol_sha256"]
        ),
        "evaluation_run_sha256": str(
            evaluation["run_sha256"]
        ),
        "sealed_holdout_sha256": str(
            evaluation["sealed_holdout_sha256"]
        ),
        "qualification_evidence_sha256": str(
            evaluation["qualification_evidence_sha256"],
        ),
        "qualification_policy_sha256": str(
            evaluation["qualification_policy_sha256"],
        ),
    }


def _verified_qualification_binding(
    *,
    evidence: Any,
    policy: Any,
    receipt_binding: Mapping[str, str] | None,
    adapter_sha256: str,
    model_improvement_policy: Mapping[str, Any] | None = None,
) -> dict[str, str] | None:
    """Evaluate the exact deployment tuple and bind it to the training run."""
    improvement_enabled = (
        _model_improvement_enabled()
        if model_improvement_policy is None
        else model_improvement_policy.get("enable") is True
    )
    if not improvement_enabled:
        return None

    from .training.qualification import (
        QualificationEvidence,
        QualificationPolicy,
        evaluate_qualification,
    )

    if not isinstance(evidence, QualificationEvidence):
        raise ValueError("model-improvement promotion requires qualification evidence")
    if not isinstance(policy, QualificationPolicy):
        raise ValueError("model-improvement promotion requires a qualification policy")
    decision = evaluate_qualification(evidence, policy)
    if not decision.qualified:
        raise ValueError(
            "deployment qualification failed: "
            + "; ".join(decision.failures[:8]),
        )
    if evidence.runtime.adapter_sha256 != adapter_sha256:
        raise ValueError("qualification covers different adapter bytes")
    if receipt_binding is None:
        raise ValueError("qualification requires a verified training receipt")
    runtime = evidence.runtime
    exact_values = {
        "training_run_id": evidence.run_id,
        "dataset_sha256": evidence.dataset_sha256,
        "base_model_id": evidence.base_model_id,
        "base_model_revision": evidence.model_revision,
        "base_model_license_id": evidence.base_model_license_id,
        "base_model_license_evidence_sha256": (
            evidence.base_model_license_evidence_sha256
        ),
        "base_model_artifact_sha256": runtime.base_model_artifact_sha256,
        "base_model_artifact_manifest_sha256": (
            runtime.base_model_artifact_manifest_sha256
        ),
        "base_model_tokenizer_sha256": runtime.base_model_tokenizer_sha256,
        "base_model_artifact_format": runtime.base_model_artifact_format,
        "adapter_artifact_format": runtime.adapter_artifact_format,
        "adapter_checkpoint_sha256": runtime.adapter_checkpoint_sha256,
        "adapter_runtime_compatibility_sha256": (
            runtime.adapter_runtime_compatibility_sha256
        ),
        "evaluation_protocol_sha256": evidence.evaluation_protocol_sha256,
        "evaluation_run_sha256": evidence.evaluation_run_sha256,
        "sealed_holdout_sha256": evidence.sealed_holdout_sha256,
        "qualification_evidence_sha256": decision.evidence_sha256,
        "qualification_policy_sha256": decision.policy_sha256,
    }
    if (
        evidence.environment_sha256s.get(receipt_binding["environment_id"])
        != receipt_binding["environment_sha256"]
    ):
        raise ValueError("qualification covers a different environment")
    for binding_field, actual in exact_values.items():
        if receipt_binding.get(binding_field) != actual:
            raise ValueError(
                "qualification and signed receipt disagree on "
                f"{binding_field}",
            )
    measured_at = datetime.fromisoformat(
        evidence.measured_at[:-1] + "+00:00",
    )
    completed_at = datetime.fromisoformat(
        receipt_binding["training_completed_at"][:-1] + "+00:00",
    )
    issued_at = datetime.fromisoformat(
        receipt_binding["receipt_issued_at"][:-1] + "+00:00",
    )
    if measured_at < completed_at or measured_at > issued_at:
        raise ValueError(
            "qualification measurement is outside the signed training-receipt timeline",
        )
    return {
        "evidence_sha256": decision.evidence_sha256,
        "policy_sha256": decision.policy_sha256,
        "runtime_attestation_sha256": decision.runtime_attestation_sha256,
        "run_id": evidence.run_id,
        "profile": policy.profile,
        "catalog_id": evidence.catalog_id,
        "catalog_sha256": evidence.catalog_sha256,
        "dataset_sha256": evidence.dataset_sha256,
        "evaluation_run_sha256": evidence.evaluation_run_sha256,
        "sealed_holdout_sha256": evidence.sealed_holdout_sha256,
        "measured_at": evidence.measured_at,
        "expires_at": decision.expires_at,
        "engine": runtime.engine,
        "engine_version": runtime.engine_version,
        "context_tokens": runtime.context_tokens,
        "concurrency": runtime.concurrency,
        "base_model_id": evidence.base_model_id,
        "base_model_revision": evidence.model_revision,
        "base_model_license_id": evidence.base_model_license_id,
        "base_model_license_evidence_sha256": (
            evidence.base_model_license_evidence_sha256
        ),
        "base_model_artifact_format": runtime.base_model_artifact_format,
        "base_model_artifact_sha256": runtime.base_model_artifact_sha256,
        "base_model_artifact_manifest_sha256": (
            runtime.base_model_artifact_manifest_sha256
        ),
        "base_model_tokenizer_sha256": runtime.base_model_tokenizer_sha256,
        "adapter_artifact_format": runtime.adapter_artifact_format,
        "adapter_checkpoint_sha256": runtime.adapter_checkpoint_sha256,
        "adapter_runtime_compatibility_sha256": (
            runtime.adapter_runtime_compatibility_sha256
        ),
        "deployment_manifest_sha256": runtime.deployment_manifest_sha256,
        "container_or_lock_sha256": runtime.container_or_lock_sha256,
        "hardware_profile_sha256": runtime.hardware_profile_sha256,
    }


def _configure_adapter_governance(
    *, keys_dir, ledger, controller, approve, approval_signature,
    approval_verifier, approval_public_keys, unsafe_dev_auto_sign,
):
    """Return a durable controller + optional external approval transport."""
    from .self_improvement import SelfImprovementController
    if approve is not None and approval_signature is not None:
        raise ValueError("provide either approve or approval_signature, not both")
    if unsafe_dev_auto_sign:
        from .enterprise import enterprise_enabled
        if enterprise_enabled():
            raise ValueError("unsafe development adapter signing is forbidden in enterprise")
        if keys_dir is None or approve is not None or approval_signature is not None:
            raise ValueError("unsafe development signing requires only keys_dir")
        approve, approval_verifier, approval_public_keys = \
            _unsafe_dev_approval_callbacks(keys_dir)
    elif keys_dir is not None:
        raise ValueError(
            "runtime private-key signing is disabled; provide an external approval "
            "callback/envelope, or explicitly enable unsafe_dev_auto_sign outside enterprise")
    else:
        approval_public_keys = _validated_approval_public_keys(approval_public_keys)

    if approval_verifier is None and getattr(controller, "approval_verifier", None) is None:
        from . import approval_signing as asig
        trusted_keys = list(approval_public_keys)

        def approval_verifier(candidate):
            signature = getattr(candidate, "approval_signature", None)
            if not signature:
                return None
            return asig.verify(
                asig.ApprovalRequest.for_candidate(candidate),
                str(signature), trusted_keys)

    if controller is None:
        # A promotion boundary must not turn a lost or malformed policy into
        # the most permissive evidence floor.  ``load_config`` is intentionally
        # fail-soft for ordinary model selection, so explicitly consult its
        # trust side-channel and validate the raw value before constructing the
        # controller.  Absence still uses the documented zero-margin default;
        # an unreadable source or a present non-numeric/out-of-range value
        # refuses promotion.
        min_imp = _adapter_min_improvement_from_config()
        controller = SelfImprovementController(
            ledger=ledger, min_improvement=min_imp,
            approval_verifier=approval_verifier)
    elif ledger is not None:
        if getattr(controller, "ledger", None) is None:
            controller.ledger = ledger
        elif controller.ledger is not ledger:
            raise ValueError("controller and adapter ledger disagree")
    if approval_verifier is not None:
        configured = getattr(controller, "approval_verifier", None)
        if configured is not None and configured is not approval_verifier:
            raise ValueError("controller and adapter approval verifier disagree")
        if configured is None:
            try:
                controller = replace(controller, approval_verifier=approval_verifier)
            except Exception as exc:
                raise ValueError(
                    "controller cannot accept a scoped approval verifier") from exc
    if getattr(controller, "approval_verifier", None) is None:
        raise ValueError(
            "governed adapter promotion requires a tenant-scoped approval verifier; "
            "use an external verifier or the explicit unsafe development signer")
    weights_policy = getattr(controller, "rung_policy", {}).get("weights", {})
    if weights_policy.get("require_human") is not True:
        raise ValueError("adapter weights policy must require cryptographic human approval")
    _require_durable_adapter_ledger(controller)
    return controller, approve, approval_public_keys


def _attach_adapter_approval(cand, *, approve, approval_signature):
    from . import approval_signing as asig
    from .self_improvement import Candidate
    signature = approval_signature
    if approve is not None:
        signature = approve(asig.ApprovalRequest.for_candidate(cand))
    if not signature:
        return cand
    return Candidate(**{**cand.__dict__, "approval_signature": str(signature)})


def _approval_key_for_candidate(cand, approval_public_keys: tuple[str, ...]) -> tuple[str, str]:
    """Return the exact trusted key and id that verify this candidate."""
    from . import approval_signing as asig
    signature = getattr(cand, "approval_signature", None)
    if not signature:
        raise ValueError("adapter approval signature is missing")
    request = asig.ApprovalRequest.for_candidate(cand)
    for public_key in approval_public_keys:
        approver_id = asig.verify(request, str(signature), [public_key])
        if approver_id:
            return public_key, approver_id
    raise ValueError("adapter approval signature is invalid for the trusted keys")


def govern_adapter_change(
    adapter_dir: Path | str,
    case_ids: list[str],
    *,
    score_fn: Callable[[str, list[str]], dict[str, bool]],
    keys_dir: Path | str | None = None,
    ledger=None,
    controller=None,
    store: AdapterStore | None = None,
    held_out_frac: float = 0.35,
    change_id: str | None = None,
    approve: Callable[[Any], str | None] | None = None,
    approval_signature: str | None = None,
    approval_verifier: Callable[[Any], str | None] | None = None,
    approval_public_keys: list[str] | tuple[str, ...] | None = None,
    serving_provisioner: Callable[[dict], dict] | None = None,
    unsafe_dev_auto_sign: bool = False,
    training_receipt_id: str | None = None,
    qualification_evidence: Any = None,
    qualification_policy: Any = None,
) -> AdapterUpliftResult:
    """Decide whether a trained adapter may be promoted and activated.

    The chain, in order (each step fails closed): payload hygiene -> manifest ->
    held-out fitness with overfit refusal -> capability non-escalation (proven
    structurally by the code-free payload boundary) -> Ed25519 human approval
    bound to the payload digest -> ``weights``-rung promotion into the
    append-only ledger -> pointer activation with the previous pointer archived
    as the one-step rollback handle."""
    from .self_improvement import Candidate

    out = AdapterUpliftResult()
    adapter_dir = Path(adapter_dir)
    st = store or AdapterStore()
    active_tenant = _active_tenant_id()
    if st.tenant_id != active_tenant:
        out.reason = (
            "adapter store tenant does not match the active execution context: "
            f"store={st.tenant_id or 'shared'!r}, active={active_tenant or 'shared'!r}")
        return out

    # Construct the controller and recover durable state before evaluating any
    # new candidate. Recovery never depends on a new payload or signing key.
    try:
        controller, approve, approval_public_keys = _configure_adapter_governance(
            keys_dir=keys_dir, ledger=ledger, controller=controller,
            approve=approve, approval_signature=approval_signature,
            approval_verifier=approval_verifier,
            approval_public_keys=approval_public_keys,
            unsafe_dev_auto_sign=unsafe_dev_auto_sign)
        recover_adapter_promotions(controller, store=st)
    except Exception as exc:
        out.reason = f"adapter governance/recovery unavailable: {exc}"
        return out

    # 1. Hygiene boundary: refuse code/pickle payloads before anything runs.
    hygiene = review_adapter_payload(adapter_dir)
    out.hygiene_ok = hygiene.ok
    if not hygiene.ok:
        out.reason = f"payload refused: {hygiene.reason}"
        return out
    try:
        manifest = AdapterManifest.load(adapter_dir)
        _require_manifest_tenant(manifest, st.tenant_id)
    except Exception as e:
        out.reason = f"unreadable adapter manifest: {e}"
        return out
    try:
        digest = payload_digest_dir(adapter_dir)
    except (OSError, ValueError) as exc:
        out.reason = f"payload digest unavailable: {exc}"
        return out
    if manifest.payload_sha256 and manifest.payload_sha256 != digest:
        out.reason = "payload digest mismatch: weights changed after training"
        return out
    # A base spec with no model id (e.g. 'ollama:') can never be served or named;
    # refuse before promotion rather than ledger an unservable adapter.
    if not _model_id(manifest.base_model).strip():
        out.reason = f"manifest base_model has no model id: {manifest.base_model!r}"
        return out
    try:
        improvement_policy = _model_improvement_policy()
        training_receipt_binding = _verified_training_receipt_binding(
            receipt_id=training_receipt_id,
            manifest=manifest,
            adapter_sha256=digest,
            model_improvement_policy=improvement_policy,
        )
    except Exception as exc:
        out.reason = f"training receipt refused: {exc}"
        return out
    try:
        qualification_binding = _verified_qualification_binding(
            evidence=qualification_evidence,
            policy=qualification_policy,
            receipt_binding=training_receipt_binding,
            adapter_sha256=digest,
            model_improvement_policy=improvement_policy,
        )
    except Exception as exc:
        out.reason = f"deployment qualification refused: {exc}"
        return out
    model_improvement_binding = (
        {
            "schema": MODEL_IMPROVEMENT_BINDING_SCHEMA,
            "policy_sha256": _model_improvement_policy_digest(
                improvement_policy,
            ),
            "training_receipt": training_receipt_binding,
            "qualification": qualification_binding,
        }
        if qualification_binding is not None
        else None
    )
    # The receipt and qualification above authorize these exact bytes. Keep
    # that digest across the later copy into immutable storage so a mutable
    # source directory cannot win a time-of-check/time-of-use race.
    authorized_digest = digest

    # 2. Fitness on the held-out split (the gate judges ONLY unseen cases).
    tuned_ref = f"{manifest.base_model}+adapter:{manifest.adapter_id}"
    out.fitness = evaluate_adapter(manifest.base_model, tuned_ref, case_ids,
                                score_fn=score_fn, held_out_frac=held_out_frac)
    if not out.fitness.ok:
        out.reason = out.fitness.reason
        return out

    try:
        adapter_dir, manifest = st.stage_payload(adapter_dir, manifest)
        digest = manifest.payload_sha256
    except Exception as exc:
        out.reason = f"adapter immutable staging failed: {exc}"
        return out
    if digest != authorized_digest:
        out.reason = (
            "adapter immutable staging refused: payload bytes changed after "
            "training receipt and qualification"
        )
        return out

    # 3. Candidate at the weights rung. Non-escalation is structural: the
    #    hygiene boundary proved the payload carries no code, and tool
    #    authority lives in the runtime capability envelope which weights
    #    cannot touch -- recorded in provenance for the audit line.
    # The exact approval payload is finalized only after non-routable serving
    # staging has produced a deployment attestation.  That lets the signature
    # bind not just the weights, but the complete pointer that can be routed.
    cand = Candidate(
        rung="weights",
        summary=(f"adapter {manifest.adapter_id} on {manifest.base_model}: held-out "
                 f"{out.fitness.baseline_score:.3f} -> {out.fitness.candidate_score:.3f}"),
        baseline_score=out.fitness.baseline_score,
        candidate_score=out.fitness.candidate_score,
        samples=out.fitness.samples,
        payload=None,
        payload_sha256=None,
        capability_widens=False,
        rollback={"artifact_identity": st.artifact_identity,
                  "action": "tenant_bound_adapter_pointer_cas_restore"},
        provenance={
            "tenant_id": st.tenant_id,
            "artifact_identity": st.artifact_identity,
            "adapter_payload_sha256": digest,
            "dataset_sha256": manifest.dataset_sha256,
            "provenance_counts": manifest.provenance_counts,
            "trainer": manifest.trainer,
            "training_receipt": training_receipt_binding,
            "qualification": qualification_binding,
            "capability_evidence": "payload hygiene boundary: no executable content; "
                                   "tool authority unchanged by weights",
        },
        id=change_id or (
            f"adapter-{_tenant_tag(st.tenant_id) + '-' if st.tenant_id else ''}"
            f"{uuid.uuid4().hex[:16]}")
    )
    out.candidate_id = cand.id

    _execute_adapter_transaction(
        out, cand=cand, manifest=manifest, adapter_dir=adapter_dir,
        controller=controller, store=st,
        serving_provisioner=serving_provisioner,
        approve=approve, approval_signature=approval_signature,
        approval_public_keys=approval_public_keys,
        allow_uninstalled_dev=unsafe_dev_auto_sign,
        model_improvement=model_improvement_binding)
    if not out.promoted:
        return out
    serve_hint = out.serving.get("create_command") or out.serving.get("note", "")
    out.reason = (f"PROMOTED: held-out {out.fitness.baseline_score:.3f} -> "
                  f"{out.fitness.candidate_score:.3f} over {out.fitness.samples} cases; "
                  f"{serve_hint}")
    return out


def rollback_adapter(record_id: str, *, store: AdapterStore | None = None,
                     ledger=None) -> dict | None:
    """Durably PREPARE, CAS, inspect, and COMMIT one pointer rollback."""
    from .self_improvement import PromotionLedgerError

    st = store or AdapterStore()
    if (ledger is None or (getattr(ledger, "path", None) is None
                           and not bool(getattr(ledger, "durable", False)))):
        raise PromotionLedgerError("adapter rollback requires a durable promotion ledger")
    if st.tenant_id != _active_tenant_id():
        raise PromotionLedgerError("adapter rollback store tenant does not match active context")
    with st.transaction_locked():
        recovered = _recover_adapter_rollback_locked(st, ledger)
        if (recovered is not None and recovered["state"] == "committed"
                and recovered["record_id"] == record_id):
            return st._read_state_locked(verify_serving=True).active
        try:
            record = ledger.get(record_id)
        except Exception as exc:
            raise PromotionLedgerError("adapter rollback authority is unavailable") from exc
        if record is None or record.rolled_back:
            raise PromotionLedgerError("adapter promotion is missing or already rolled back")
        record_tenant = _validated_tenant_id(record.provenance.get("tenant_id", ""))
        if record_tenant != st.tenant_id:
            raise PromotionLedgerError("adapter rollback receipt belongs to another tenant")
        before = st._read_state_locked(verify_serving=True)
        if before.pending_rollback is not None:
            raise PromotionLedgerError("adapter rollback recovery is required")
        if (before.active is None
                or before.active.get("promotion_record_id") != record_id):
            raise PromotionLedgerError("adapter rollback target is not the active promotion")
        if before.active.get("authority") == "governed-v1":
            _verify_authoritative_pointer(
                before.active, artifact_identity=st.artifact_identity)
        after = _PointerState(
            active=before.previous, previous=None, pending_rollback=None)
        if after.active is not None:
            _verify_serving_binding(after.active.get("serving"))
            if after.active.get("authority") == "governed-v1":
                _verify_authoritative_pointer(
                    after.active, artifact_identity=st.artifact_identity)
        before_revision = st._revision(before)
        after_revision = st._revision(after)
        intent = {
            "version": 1,
            "transaction_id": f"adapter-rollback:{record_id}",
            "record_id": record_id,
            "tenant_id": st.tenant_id,
            "prepared_at": time.time(),
            "before": before_revision.to_dict(),
            "after": after_revision.to_dict(),
        }
        # PREPARE is an authoritative part of pointer-state. A process death
        # after either following write is deterministically recoverable.
        st._write_state_locked(_PointerState(
            active=before.active, previous=before.previous,
            pending_rollback=intent))
        applied = _PointerState(
            active=after.active, previous=after.previous,
            pending_rollback=intent)
        st._write_state_locked(applied)
        observed = st._read_state_locked(verify_serving=True)
        if st._revision(observed) != after_revision:
            raise PromotionLedgerError("adapter rollback pointer inspection failed")
        try:
            ledger.mark_rolled_back(record_id, at=time.time())
            authoritative = ledger.get(record_id)
        except Exception as exc:
            raise PromotionLedgerError(
                "adapter rollback COMMIT is in doubt; recovery required") from exc
        if authoritative is None or not authoritative.rolled_back:
            raise PromotionLedgerError(
                "adapter rollback COMMIT is in doubt; recovery required")
        st._write_state_locked(_PointerState(
            active=after.active, previous=after.previous, pending_rollback=None))
        return after.active
