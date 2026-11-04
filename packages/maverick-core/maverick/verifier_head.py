"""Torch-free CPU training for the judgment rung, end to end.

The self-improvement architecture is "an empty gym" until a real reward model
trains on real trajectories. This is the cheapest possible
proof that the gym works -- a tiny linear head over the 12-dim PRM step features
that trains on captured trajectories with plain gradient descent (no torch, no
GPU, no numpy), is evaluated by how well it *separates* promising from
unpromising steps, and is adopted only through the governed artifact
PREPARE/apply/COMMIT protocol. It is the verifier rung made real on a laptop;
the torch MLP in
``training/prm_train.py`` is the scale-up, not the prerequisite.

Deterministic (seeded) and offline -- a unit test trains it on synthetic
trajectories and checks it both learns and gets gated correctly.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import threading
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

FEATURE_DIM = 12   # must match prm.step_features
OUT_DIM = 2        # (promise, progress)


def _retry_windows_file_op(operation):
    """Retry short-lived Windows sharing violations, never other failures."""
    for attempt in range(8):
        try:
            return operation()
        except PermissionError:
            if os.name != "nt" or attempt == 7:
                raise
            # Antivirus/indexers and a reader in another process can briefly
            # deny an atomic replace. The bounded backoff is at most 255 ms.
            time.sleep(0.001 * (2 ** attempt))
    raise AssertionError("unreachable")


def _sync_durable_path(path: Path) -> None:
    """Flush a committed small file and, where supported, its directory."""
    with path.open("rb+") as handle:
        os.fsync(handle.fileno())
    try:
        descriptor = os.open(path.parent, os.O_RDONLY)
    except OSError:  # Windows and some network filesystems reject directory FDs
        return
    try:
        os.fsync(descriptor)
    except OSError:  # pragma: no cover - directory fsync is platform-specific
        pass
    finally:
        os.close(descriptor)


@dataclass
class LinearHead:
    """A serving-compatible 12 -> 2 tanh-linear PRM head.

    ``LinearPRM`` applies ``tanh`` at inference, so training and local
    evaluation must do the same.  Keeping this transform here prevents a head
    from winning its held-out gate under one function and serving another.
    """

    w: list[list[float]] = field(
        default_factory=lambda: [[0.0] * FEATURE_DIM for _ in range(OUT_DIM)])
    b: list[float] = field(default_factory=lambda: [0.0] * OUT_DIM)

    def predict(self, features: list[float]) -> list[float]:
        if len(features) != FEATURE_DIM:
            raise ValueError(f"features must have length {FEATURE_DIM}")
        out = []
        for o in range(OUT_DIM):
            row = self.w[o]
            z = self.b[o] + sum(row[i] * features[i] for i in range(FEATURE_DIM))
            out.append(math.tanh(z))
        return out

    def promise(self, features: list[float]) -> float:
        return self.predict(features)[0]

    def to_dict(self) -> dict:
        """Return the exact safe-JSON schema consumed by :class:`LinearPRM`."""
        from .prm import FEATURE_NAMES, ROLE_VOCAB

        return {
            "kind": "linear",
            "schema_version": 1,
            "feature_names": list(FEATURE_NAMES),
            "role_vocab": list(ROLE_VOCAB),
            "input_dim": FEATURE_DIM,
            "promise": {"w": list(self.w[0]), "b": self.b[0]},
            "progress": {"w": list(self.w[1]), "b": self.b[1]},
        }

    @classmethod
    def from_dict(cls, d: dict) -> LinearHead:
        """Read the serving schema and the pre-schema ``w``/``b`` format."""
        if not isinstance(d, dict):
            raise ValueError("linear head artifact must be an object")
        if "promise" in d or "progress" in d:
            from .prm import LinearPRM

            pw, pb, gw, gb = LinearPRM._head_from_meta(d)
            return cls(w=[pw, gw], b=[pb, gb])

        # Backward read compatibility for heads saved before verifier artifacts
        # shared the serving schema.  Legacy data is still validated strictly;
        # compatibility must not turn malformed/non-finite weights into a model.
        try:
            rows = d["w"]
            bias = d["b"]
            if (not isinstance(rows, list) or len(rows) != OUT_DIM
                    or not isinstance(bias, list) or len(bias) != OUT_DIM):
                raise ValueError("legacy linear head dimensions do not match")
            weights = [list(map(float, row)) for row in rows]
            offsets = list(map(float, bias))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid legacy linear head") from exc
        if any(len(row) != FEATURE_DIM for row in weights):
            raise ValueError("legacy linear head feature dimension does not match")
        if not all(math.isfinite(value) for row in weights for value in row):
            raise ValueError("legacy linear head weights must be finite")
        if not all(math.isfinite(value) for value in offsets):
            raise ValueError("legacy linear head biases must be finite")
        return cls(w=weights, b=offsets)

    def save(self, path: str | Path) -> None:
        # Atomic temp+replace: a bare write_text truncates in place, so a serving
        # process re-loading the head while a training run writes it would see a
        # half-written file and json.load would raise.  The in-process path lock
        # also avoids Windows denying replace while this module has the target
        # open for a concurrent read.
        from .file_lock import atomic_write_text

        target = Path(path)
        with _activation_lock(target):
            payload = json.dumps(self.to_dict(), sort_keys=True, allow_nan=False)
            _retry_windows_file_op(
                lambda: atomic_write_text(target, payload),
            )

    @classmethod
    def load(cls, path: str | Path) -> LinearHead:
        target = Path(path)
        with _activation_lock(target):
            payload = target.read_text(encoding="utf-8")
        return cls.from_dict(json.loads(payload))


@dataclass(frozen=True)
class StagedVerifierArtifact:
    """An immutable, content-addressed verifier artifact awaiting activation."""

    path: Path
    sha256: str
    version: str


class VerifierRecoveryRequired(RuntimeError):
    """The active verifier has an unresolved write-ahead transaction."""


_ACTIVATION_LOCKS: dict[str, threading.RLock] = {}
_ACTIVATION_LOCKS_GUARD = threading.Lock()


def _path_key(path: Path) -> str:
    # Pure lexical normalization: ``Path.resolve()`` can touch/open the target
    # on Windows before this lock is acquired and race an in-flight replace.
    return os.path.normcase(os.path.abspath(os.fspath(Path(path).expanduser())))


def _absolute_path(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _activation_lock(path: Path) -> threading.RLock:
    key = _path_key(path)
    with _ACTIVATION_LOCKS_GUARD:
        return _ACTIVATION_LOCKS.setdefault(key, threading.RLock())


_ABSENT_ARTIFACT_SHA256 = hashlib.sha256(b"").hexdigest()
_ROLLBACK_MANIFEST_SCHEMA = 1
_MAX_ROLLBACK_MANIFEST_BYTES = 16 * 1024


def _artifact_identity(path: Path) -> str:
    """Stable ledger identity for the one active verifier serving path."""
    return f"linear-prm-file:{_path_key(path)}"


def _read_active_bytes(path: Path) -> tuple[bool, bytes | None]:
    try:
        return True, path.read_bytes()
    except (FileNotFoundError, NotADirectoryError):
        return False, None


def _artifact_revision(identity: str, existed: bool, payload: bytes | None):
    from .self_improvement import ArtifactRevision

    if not existed:
        return ArtifactRevision(
            identity=identity, sha256=_ABSENT_ARTIFACT_SHA256, version="absent",
        )
    if payload is None:  # pragma: no cover - kept explicit for type narrowing
        raise ValueError("existing verifier artifact has no bytes")
    digest = hashlib.sha256(payload).hexdigest()
    return ArtifactRevision(
        identity=identity, sha256=digest, version=f"linear-v1-{digest}",
    )


@dataclass
class VerifierActivation:
    """Write-ahead activation plan with a concrete, concurrency-safe undo.

    The plan is created before the governance gate, so its bound ``rollback``
    method is the candidate's real reversibility handle.  Governed callers hold
    :meth:`locked` across durable PREPARE, atomic activation, and durable COMMIT.
    Rollback refuses to overwrite an unrelated newer deployment.
    """

    artifact: StagedVerifierArtifact
    active_path: Path
    artifact_dir: Path
    identity: str = ""
    _previous: bytes | None = field(default=None, init=False, repr=False)
    _previous_existed: bool = field(default=False, init=False, repr=False)
    _started: bool = field(default=False, init=False, repr=False)
    _active: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self.active_path = _absolute_path(self.active_path)
        self.artifact_dir = _absolute_path(self.artifact_dir)
        expected = _artifact_identity(self.active_path)
        if self.identity and self.identity != expected:
            raise ValueError("verifier artifact identity does not match active path")
        self.identity = expected

    @staticmethod
    def _digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @property
    def after_revision(self):
        from .self_improvement import ArtifactRevision

        return ArtifactRevision(
            identity=self.identity,
            sha256=self.artifact.sha256,
            version=self.artifact.version,
        )

    @contextmanager
    def locked(self):
        """Serialize observe/PREPARE/apply/COMMIT for this active artifact."""
        from .file_lock import cross_process_lock

        lock = _activation_lock(self.active_path)
        with lock, cross_process_lock(self.active_path):
            yield

    def _current_revision_locked(self, identity: str | None = None):
        if identity is not None and identity != self.identity:
            raise ValueError("verifier artifact identity does not match deployment")
        existed, payload = _read_active_bytes(self.active_path)
        return _artifact_revision(self.identity, existed, payload)

    def _validated_staged_payload(self) -> tuple[bytes, object]:
        """Read, hash, and parse the staged bytes as one immutable snapshot."""
        from .prm import MAX_LINEAR_PRM_ARTIFACT_BYTES, LinearPRM

        with _activation_lock(self.artifact.path):
            payload = self.artifact.path.read_bytes()
        if len(payload) > MAX_LINEAR_PRM_ARTIFACT_BYTES:
            raise ValueError("linear PRM artifact exceeds size limit")
        if hashlib.sha256(payload).hexdigest() != self.artifact.sha256:
            raise ValueError("linear PRM artifact digest mismatch")
        try:
            meta = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("linear PRM artifact is not valid UTF-8 JSON") from exc
        LinearPRM._head_from_meta(meta)
        return payload, meta

    def evaluation_head(self) -> LinearHead:
        """Return the exact digest-bound head represented by ``after_revision``."""
        _payload, meta = self._validated_staged_payload()
        return LinearHead.from_dict(meta)

    def current_revision(self):
        """Return the current stable-path revision under the artifact lock."""
        with self.locked():
            return self._current_revision_locked()

    def activate(self, *, expected_before=None) -> None:
        """Atomically install the staged artifact, optionally with before-CAS."""
        with self.locked():
            self._activate_locked(expected_before=expected_before)

    def _activate_locked(self, *, expected_before=None) -> None:
        """Install while the caller holds :meth:`locked`."""
        from .file_lock import atomic_write_bytes

        if self._started:
            raise RuntimeError("verifier activation plan is single-use")
        current = self._current_revision_locked()
        if expected_before is not None and current != expected_before:
            raise RuntimeError("active verifier changed since promotion PREPARE")
        self._persist_predecessor_locked(current)
        # Read/hash/parse once. A validate-then-read sequence would let an
        # attacker swap the staged path between those operations.
        payload, _meta = self._validated_staged_payload()
        self._previous_existed, self._previous = _read_active_bytes(self.active_path)
        self._started = True
        _retry_windows_file_op(
            lambda: atomic_write_bytes(self.active_path, payload, mode=0o600),
        )
        from .prm import LinearPRM

        LinearPRM.validate_artifact(
            self.active_path, expected_sha256=self.artifact.sha256,
        )
        if self._current_revision_locked() != self.after_revision:
            raise RuntimeError("activated verifier revision does not match staged artifact")
        self._active = True

    @property
    def rollback_manifest_path(self) -> Path:
        return self.artifact_dir / "rollbacks" / f"{self.artifact.sha256}.json"

    def _persist_predecessor_locked(self, expected_before) -> Path:
        """Durably retain the exact predecessor and its restoration mapping.

        This runs after durable PREPARE but before activation and COMMIT.
        Orphaned mappings after a failed apply are harmless; losing predecessor
        bytes after COMMIT is not.
        """
        from .file_lock import atomic_write_bytes, atomic_write_text
        from .prm import LinearPRM

        existed, payload = _read_active_bytes(self.active_path)
        observed = _artifact_revision(self.identity, existed, payload)
        if observed != expected_before:
            raise RuntimeError("active verifier changed before predecessor snapshot")
        if existed:
            if payload is None:  # pragma: no cover - narrowed by _read_active_bytes
                raise RuntimeError("existing verifier predecessor has no bytes")
            predecessor_path = (
                self.artifact_dir / "versions"
                / f"linear-v1-{expected_before.sha256}.json"
            )
            if predecessor_path.exists():
                if hashlib.sha256(predecessor_path.read_bytes()).hexdigest() != (
                    expected_before.sha256
                ):
                    raise RuntimeError("persisted verifier predecessor was modified")
            else:
                _retry_windows_file_op(
                    lambda: atomic_write_bytes(predecessor_path, payload, mode=0o600),
                )
            _sync_durable_path(predecessor_path)
            LinearPRM.validate_artifact(
                predecessor_path, expected_sha256=expected_before.sha256,
            )
        manifest = {
            "schema_version": _ROLLBACK_MANIFEST_SCHEMA,
            "identity": self.identity,
            "before": expected_before.to_dict(),
            "after": self.after_revision.to_dict(),
        }
        encoded = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        path = self.rollback_manifest_path
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError) as exc:
                raise RuntimeError("verifier rollback mapping is unreadable") from exc
            if existing != manifest:
                raise RuntimeError("verifier rollback mapping conflicts with candidate")
        else:
            _retry_windows_file_op(
                lambda: atomic_write_text(path, encoded + "\n", mode=0o600),
            )
        _sync_durable_path(path)
        self._previous_existed, self._previous = existed, payload
        return path

    def rollback(self) -> None:
        """Restore the exact predecessor, without clobbering a newer head."""
        from .file_lock import atomic_write_bytes

        if not self._started:
            # A failed pre-write validation has no runtime state to undo.  This
            # remains a valid rollback outcome and lets the controller durably
            # mark its already-committed receipt as rolled back.
            return
        with self.locked():
            current_existed, current = _read_active_bytes(self.active_path)
            current_digest = self._digest(current) if current is not None else None
            previous_digest = (
                self._digest(self._previous) if self._previous is not None else None
            )
            if current_digest == self.artifact.sha256:
                if self._previous_existed and self._previous is not None:
                    _retry_windows_file_op(
                        lambda: atomic_write_bytes(
                            self.active_path, self._previous, mode=0o600,
                        ),
                    )
                else:
                    try:
                        _retry_windows_file_op(self.active_path.unlink)
                    except FileNotFoundError:
                        pass
            elif (current_existed != self._previous_existed
                  or current_digest != previous_digest):
                raise RuntimeError(
                    "active verifier changed after activation; refusing to clobber it"
                )
            self._active = False


@dataclass(frozen=True)
class VerifierArtifactDeployment:
    """Content-addressed staging plus atomic activation at a serving path.

    ``active_path`` is the stable path configured as ``MAVERICK_PRM_PATH``.
    Every candidate remains available under ``artifact_dir/versions`` by its
    digest-derived version; serving never points at a partially written file.
    """

    artifact_dir: Path
    active_path: Path
    bootstrap_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_dir", _absolute_path(self.artifact_dir))
        object.__setattr__(self, "active_path", _absolute_path(self.active_path))
        digest = self.bootstrap_sha256
        if digest is not None:
            if not isinstance(digest, str):
                raise ValueError("bootstrap_sha256 must be a SHA-256 string or None")
            digest = digest.lower()
            if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValueError("bootstrap_sha256 must be 64 hexadecimal characters")
            object.__setattr__(self, "bootstrap_sha256", digest)

    @property
    def identity(self) -> str:
        return _artifact_identity(Path(self.active_path))

    @property
    def bootstrap_revision(self):
        """Return the explicitly provisioned root of artifact authority.

        With no configured bootstrap, the only trusted root is an absent
        artifact.  Merely placing valid JSON at the serving path never grants
        it authority.
        """
        from .self_improvement import ArtifactRevision

        if self.bootstrap_sha256 is None:
            return ArtifactRevision(
                identity=self.identity,
                sha256=_ABSENT_ARTIFACT_SHA256,
                version="absent",
            )
        return ArtifactRevision(
            identity=self.identity,
            sha256=self.bootstrap_sha256,
            version=f"linear-v1-{self.bootstrap_sha256}",
        )

    def authoritative_revision(self, controller):
        """Derive the one authorized revision from the durable ledger chain.

        Authority starts at the explicit bootstrap (or the absent state) and
        advances only across contiguous committed transactions. A rollback
        moves the chain back to that transaction's predecessor. Any fork,
        missing durable ledger, or in-doubt transaction fails closed.
        """
        ledger = getattr(controller, "ledger", None)
        if ledger is None or getattr(ledger, "path", None) is None:
            raise VerifierRecoveryRequired(
                "verifier authority requires a durable promotion ledger"
            )
        if ledger.in_doubt(artifact_identity=self.identity):
            raise VerifierRecoveryRequired(
                "active verifier promotion is still in doubt"
            )
        try:
            transactions = ledger.transactions(
                artifact_identity=self.identity, state="committed",
            )
        except Exception as exc:
            raise VerifierRecoveryRequired(
                "verifier promotion authority could not be read"
            ) from exc

        revision = self.bootstrap_revision
        for transaction in transactions:
            if transaction.before != revision:
                raise VerifierRecoveryRequired(
                    "verifier promotion ledger is not a contiguous authority chain"
                )
            revision = (
                transaction.before
                if transaction.record.rolled_back
                else transaction.after
            )
        return revision

    def inspect(self, identity: str):
        """Trusted recovery inspector for this deployment's stable path."""
        active_path = Path(self.active_path)
        if identity != self.identity:
            raise ValueError("verifier artifact identity does not match deployment")
        from .file_lock import cross_process_lock

        with _activation_lock(active_path), cross_process_lock(active_path):
            existed, payload = _read_active_bytes(active_path)
            return _artifact_revision(self.identity, existed, payload)

    def snapshot_for_evaluation(self, controller):
        """Freeze the exact authorized incumbent head and revision together."""
        from .file_lock import cross_process_lock
        from .prm import LinearPRM

        active_path = Path(self.active_path)
        with _activation_lock(active_path), cross_process_lock(active_path):
            authorized = self.authoritative_revision(controller)
            existed, payload = _read_active_bytes(active_path)
            observed = _artifact_revision(self.identity, existed, payload)
            if observed != authorized:
                raise VerifierRecoveryRequired(
                    "incumbent verifier is not authorized for evaluation"
                )
            if not existed:
                return LinearHead(), observed, "trivial_absent_zero"
            if payload is None:  # pragma: no cover - narrowed by read helper
                raise VerifierRecoveryRequired(
                    "authorized incumbent verifier has no bytes"
                )
            try:
                LinearPRM.validate_artifact(
                    active_path, expected_sha256=observed.sha256,
                )
                head = LinearHead.from_dict(json.loads(payload.decode("utf-8")))
            except (OSError, UnicodeError, TypeError, ValueError) as exc:
                raise VerifierRecoveryRequired(
                    "authorized incumbent verifier is not loadable"
                ) from exc
            return head, observed, "deployed_authorized"

    def recover(self, controller):
        """Resolve crash-left PREPAREs from the current active-path revision."""
        from .file_lock import cross_process_lock

        active_path = Path(self.active_path)
        with _activation_lock(active_path), cross_process_lock(active_path):
            def inspect_locked(identity: str):
                if identity != self.identity:
                    raise ValueError(
                        "verifier artifact identity does not match deployment")
                existed, payload = _read_active_bytes(active_path)
                return _artifact_revision(self.identity, existed, payload)

            return controller.recover_promotions(
                inspect_locked, artifact_identity=self.identity,
            )

    def recover_for_serving(self, controller):
        """Reconcile startup state or refuse to expose the active artifact."""
        recovered = self.recover(controller)
        unresolved = [transaction for transaction in recovered if transaction.in_doubt]
        if unresolved:
            raise VerifierRecoveryRequired(
                "active verifier promotion remains in doubt after recovery"
            )
        # A schema-valid file is not authority.  Recompute the exact ledger
        # chain after recovery and compare it to the bytes that would serve.
        authorized = self.authoritative_revision(controller)
        observed = self.inspect(self.identity)
        if observed != authorized:
            raise VerifierRecoveryRequired(
                "active verifier revision is not authorized by the promotion ledger"
            )
        return recovered

    def authority_resolver(self, controller):
        """Return a serving callback that rechecks ledger authority on reload."""
        return lambda: self.authoritative_revision(controller)

    def consume_confirmation(
        self, controller, *, cohort_sha256: str, before, after,
    ) -> Path:
        """Durably consume a sealed confirmation cohort exactly once.

        The receipt is created *before* either head is scored. ``O_EXCL`` makes
        concurrent/restarted attempts with the same cohort fail closed, even
        when the first candidate loses or crashes. This prevents adaptive model
        selection against what is supposed to remain confirmation evidence.
        """
        from .file_lock import cross_process_lock

        if (not isinstance(cohort_sha256, str) or len(cohort_sha256) != 64
                or any(ch not in "0123456789abcdef" for ch in cohort_sha256)):
            raise ValueError("cohort_sha256 must be a lowercase SHA-256 digest")
        if (getattr(before, "identity", None) != self.identity
                or getattr(after, "identity", None) != self.identity):
            raise ValueError("confirmation artifact identity does not match deployment")
        active_path = Path(self.active_path)
        with _activation_lock(active_path), cross_process_lock(active_path):
            existed, payload = _read_active_bytes(active_path)
            observed = _artifact_revision(self.identity, existed, payload)
            if observed != before or self.authoritative_revision(controller) != before:
                raise VerifierRecoveryRequired(
                    "incumbent changed before confirmation cohort consumption"
                )
            receipt = {
                "schema_version": 1,
                "protocol": "paired-task-v1",
                "cohort_sha256": cohort_sha256,
                "before": before.to_dict(),
                "challenger": after.to_dict(),
                "consumed_at": time.time(),
            }
            encoded = (
                json.dumps(
                    receipt, sort_keys=True, separators=(",", ":"),
                    allow_nan=False,
                ) + "\n"
            ).encode("utf-8")
            path = Path(self.artifact_dir) / "evaluations" / f"{cohort_sha256}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_BINARY", 0)
            try:
                descriptor = os.open(path, flags, 0o600)
            except FileExistsError as exc:
                raise VerifierRecoveryRequired(
                    "confirmation cohort has already been consumed"
                ) from exc
            try:
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:  # pragma: no cover - OS contract guard
                        raise OSError("short confirmation receipt write")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                parent_descriptor = os.open(path.parent, os.O_RDONLY)
            except OSError:
                parent_descriptor = None
            if parent_descriptor is not None:
                try:
                    os.fsync(parent_descriptor)
                except OSError:  # pragma: no cover - platform-specific
                    pass
                finally:
                    os.close(parent_descriptor)
            return path

    @staticmethod
    def _revision_from_manifest(raw: object, *, label: str):
        from .self_improvement import ArtifactRevision

        if not isinstance(raw, Mapping) or set(raw) != {
            "identity", "sha256", "version",
        }:
            raise VerifierRecoveryRequired(
                f"verifier rollback {label} revision is malformed"
            )
        try:
            return ArtifactRevision(
                identity=raw["identity"],
                sha256=raw["sha256"],
                version=raw["version"],
            )
        except (TypeError, ValueError) as exc:
            raise VerifierRecoveryRequired(
                f"verifier rollback {label} revision is invalid"
            ) from exc

    def _load_rollback_manifest(self, transaction):
        path = Path(self.artifact_dir) / "rollbacks" / f"{transaction.after.sha256}.json"
        try:
            if path.stat().st_size > _MAX_ROLLBACK_MANIFEST_BYTES:
                raise VerifierRecoveryRequired("verifier rollback mapping is oversized")
            payload = path.read_bytes()
            if len(payload) > _MAX_ROLLBACK_MANIFEST_BYTES:
                raise VerifierRecoveryRequired("verifier rollback mapping is oversized")
            raw = json.loads(payload.decode("utf-8"))
        except VerifierRecoveryRequired:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise VerifierRecoveryRequired(
                "verifier rollback mapping is unreadable"
            ) from exc
        if not isinstance(raw, Mapping) or set(raw) != {
            "schema_version", "identity", "before", "after",
        } or raw.get("schema_version") != _ROLLBACK_MANIFEST_SCHEMA:
            raise VerifierRecoveryRequired("verifier rollback mapping is malformed")
        before = self._revision_from_manifest(raw["before"], label="before")
        after = self._revision_from_manifest(raw["after"], label="after")
        if (raw["identity"] != self.identity or before != transaction.before
                or after != transaction.after):
            raise VerifierRecoveryRequired(
                "verifier rollback mapping does not match committed transaction"
            )
        return before, after

    def rollback_committed(self, controller, record_id: str) -> bool:
        """Restore a committed verifier after restart, then receipt rollback.

        The predecessor is read from a content-addressed durable snapshot, not
        an in-memory closure. The active artifact is compared-and-swapped from
        the exact committed ``after`` revision. If the rollback receipt cannot
        be persisted, the exact ``after`` bytes are restored best-effort so the
        runtime and authority ledger do not silently diverge.
        """
        from .file_lock import atomic_write_bytes, cross_process_lock
        from .prm import LinearPRM

        ledger = getattr(controller, "ledger", None)
        if ledger is None or getattr(ledger, "path", None) is None:
            return False
        try:
            matches = [
                tx for tx in ledger.transactions(
                    artifact_identity=self.identity, state="committed",
                )
                if tx.record.id == record_id
            ]
        except Exception:
            log.warning("verifier rollback authority lookup failed", exc_info=True)
            return False
        if len(matches) != 1 or matches[0].record.rolled_back:
            return False
        transaction = matches[0]
        try:
            before, after = self._load_rollback_manifest(transaction)
            if self.authoritative_revision(controller) != after:
                return False
        except VerifierRecoveryRequired:
            log.warning("verifier rollback mapping/authority invalid", exc_info=True)
            return False

        active_path = Path(self.active_path)
        with _activation_lock(active_path), cross_process_lock(active_path):
            existed, after_payload = _read_active_bytes(active_path)
            if _artifact_revision(self.identity, existed, after_payload) != after:
                return False
            predecessor_payload: bytes | None = None
            if before.version != "absent":
                predecessor_path = (
                    Path(self.artifact_dir) / "versions"
                    / f"linear-v1-{before.sha256}.json"
                )
                try:
                    LinearPRM.validate_artifact(
                        predecessor_path, expected_sha256=before.sha256,
                    )
                    predecessor_payload = predecessor_path.read_bytes()
                except (OSError, TypeError, ValueError):
                    log.warning("verifier predecessor artifact is unavailable", exc_info=True)
                    return False

            def restore_before() -> None:
                if predecessor_payload is None:
                    try:
                        _retry_windows_file_op(active_path.unlink)
                    except FileNotFoundError:
                        pass
                else:
                    _retry_windows_file_op(
                        lambda: atomic_write_bytes(
                            active_path, predecessor_payload, mode=0o600,
                        ),
                    )

            if not controller.rollback(record_id, undo=restore_before):
                # ``controller.rollback`` may have restored bytes but failed to
                # journal its receipt. Put the committed artifact back so a
                # subsequent authority check remains fail-closed and coherent.
                if after_payload is not None:
                    try:
                        _retry_windows_file_op(
                            lambda: atomic_write_bytes(
                                active_path, after_payload, mode=0o600,
                            ),
                        )
                    except OSError:
                        log.critical(
                            "could not restore verifier after rollback receipt failure",
                            exc_info=True,
                        )
                return False
            observed, payload = _read_active_bytes(active_path)
            if _artifact_revision(self.identity, observed, payload) != before:
                raise VerifierRecoveryRequired(
                    "verifier rollback receipt committed but predecessor is not active"
                )
        return self.authoritative_revision(controller) == before

    def stage(self, head: LinearHead) -> VerifierActivation:
        from .file_lock import atomic_write_bytes
        from .prm import LinearPRM

        artifact_dir = Path(self.artifact_dir)
        active_path = Path(self.active_path)
        encoded = (
            json.dumps(
                head.to_dict(), sort_keys=True, separators=(",", ":"),
                allow_nan=False,
            ) + "\n"
        ).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        # Use the full digest in the version identity. Truncation is convenient
        # for display but unnecessarily weakens a content-addressed namespace.
        version = f"linear-v1-{digest}"
        version_path = artifact_dir / "versions" / f"{version}.json"
        if _path_key(version_path) == _path_key(active_path):
            raise ValueError("staged and active verifier paths must be different")
        if version_path.exists():
            if hashlib.sha256(version_path.read_bytes()).hexdigest() != digest:
                raise ValueError("content-addressed verifier artifact was modified")
        else:
            _retry_windows_file_op(
                lambda: atomic_write_bytes(version_path, encoded, mode=0o600),
            )
        LinearPRM.validate_artifact(version_path, expected_sha256=digest)
        return VerifierActivation(
            artifact=StagedVerifierArtifact(
                path=version_path, sha256=digest, version=version,
            ),
            active_path=active_path,
            artifact_dir=artifact_dir,
            identity=self.identity,
        )


def _target(ex: dict) -> list[float | None]:
    """Return only observed, finite targets.

    Outcome supervision supplies a promise/value label but usually cannot claim
    per-step progress.  Missing progress therefore masks that output's loss
    instead of silently manufacturing a zero target.
    """
    out: list[float | None] = []
    for name in ("promise", "progress"):
        raw = ex.get(name)
        if raw is None:
            out.append(None)
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            out.append(None)
            continue
        out.append(value if math.isfinite(value) else None)
    return out


def _weight(ex: dict) -> float:
    """Finite non-negative per-row weight (legacy rows default to one)."""
    try:
        value = float(ex.get("weight", 1.0))
    except (TypeError, ValueError):
        return 0.0
    return value if math.isfinite(value) and value >= 0.0 else 0.0


def train(examples: list[dict], *, epochs: int = 300, lr: float = 0.05,
          seed: int = 0) -> LinearHead:
    """Plain SGD on MSE. Pure Python; deterministic for a given seed."""
    head = LinearHead()
    if not examples:
        return head
    rng = random.Random(seed)
    idx = list(range(len(examples)))
    for _ in range(epochs):
        rng.shuffle(idx)
        for j in idx:
            ex = examples[j]
            x = ex["features"]
            pred = head.predict(x)
            tgt = _target(ex)
            for o in range(OUT_DIM):
                if tgt[o] is None:
                    continue
                # Serving applies tanh, so optimize through that same transform:
                # d/dz 0.5*(tanh(z)-y)^2 = error * (1-prediction^2).
                err = ((pred[o] - tgt[o]) * (1.0 - pred[o] * pred[o])
                       * _weight(ex))
                for i in range(FEATURE_DIM):
                    head.w[o][i] -= lr * err * x[i]
                head.b[o] -= lr * err
    return head


def mse(head: LinearHead, examples: list[dict]) -> float:
    if not examples:
        return 0.0
    total = 0.0
    observed = 0.0
    for ex in examples:
        pred = head.predict(ex["features"])
        tgt = _target(ex)
        for o in range(OUT_DIM):
            if tgt[o] is None:
                continue
            weight = _weight(ex)
            total += weight * (pred[o] - tgt[o]) ** 2
            observed += weight
    return total / observed if observed else 0.0


def baseline_mse(train_ex: list[dict], test_ex: list[dict]) -> float:
    """MSE of the trivial predictor (mean target from train) on the test set."""
    if not train_ex or not test_ex:
        return 0.0
    mean: list[float | None] = []
    for o in range(OUT_DIM):
        values = [(target, _weight(e)) for e in train_ex
                  if (target := _target(e)[o]) is not None and _weight(e) > 0]
        denom = sum(weight for _, weight in values)
        mean.append((sum(value * weight for value, weight in values) / denom)
                    if denom else None)
    total = 0.0
    observed = 0.0
    for ex in test_ex:
        tgt = _target(ex)
        for o in range(OUT_DIM):
            if mean[o] is None or tgt[o] is None:
                continue
            weight = _weight(ex)
            total += weight * (mean[o] - tgt[o]) ** 2
            observed += weight
    return total / observed if observed else 0.0


def discrimination(head: LinearHead, examples: list[dict]) -> float:
    """Mean predicted promise on genuinely-promising steps minus on unpromising
    ones (split at the median actual promise). 0 for a constant predictor; the
    signal the ``propose_verifier`` gate scores."""
    if len(examples) < 4:
        return 0.0
    labelled = [(e, _target(e)[0]) for e in examples]
    labelled = [(e, promise) for e, promise in labelled if promise is not None]
    # Provenance-aware evaluation counts each independent task once. Aggregate
    # its steps before measuring separation so verbosity cannot manufacture
    # either apparent accuracy or a larger promotion effect.
    if labelled and all(e.get("task_id") is not None for e, _ in labelled):
        grouped: dict[str, list[tuple[dict, float]]] = {}
        for ex, promise in labelled:
            grouped.setdefault(str(ex["task_id"]), []).append((ex, promise))
        task_rows: list[tuple[dict, float]] = []
        for task, rows in grouped.items():
            task_rows.append((
                {"features": [
                    sum(float(ex["features"][i]) for ex, _ in rows) / len(rows)
                    for i in range(FEATURE_DIM)
                ], "task_id": task},
                sum(promise for _, promise in rows) / len(rows),
            ))
        labelled = task_rows
    if len(labelled) < 4:
        return 0.0
    promises = [promise for _, promise in labelled]
    low, high = min(promises), max(promises)
    if low == high:
        return 0.0
    # Promise outcomes are commonly binary. A median split with ``>=`` becomes
    # empty on one side whenever the held-out task count is imbalanced (e.g.
    # five failures/four successes), turning a real signal into exactly zero.
    # The midpoint of the observed bounded target range preserves both classes.
    threshold = (low + high) / 2.0
    hi = [head.promise(e["features"]) for e, promise in labelled if promise > threshold]
    lo = [head.promise(e["features"]) for e, promise in labelled if promise <= threshold]
    if not hi or not lo:
        return 0.0
    return (sum(hi) / len(hi)) - (sum(lo) / len(lo))


def group_temporal_split(
    examples: list[dict], *, split: float = 0.3,
) -> tuple[list[dict], list[dict]]:
    """Keep repeated tasks/episodes together and test only on later outcomes.

    ``task_id`` (falling back to ``goal_id``) is the leakage boundary: all
    attempts and episodes for one task stay in one arm. Groups are ordered by
    their latest verified-outcome timestamp, with the newest groups reserved for
    testing. Missing identity/time metadata is rejected rather than quietly
    reverting to a step-level random split.
    """
    if not 0.0 < float(split) < 1.0:
        raise ValueError("split must be between 0 and 1")
    groups: dict[str, list[dict]] = {}
    group_time: dict[str, float] = {}
    for ex in examples:
        task = ex.get("task_id", ex.get("goal_id"))
        episode = ex.get("episode_id")
        stamp = ex.get("outcome_verified_at")
        if task is None or episode is None or stamp is None:
            raise ValueError("group/temporal split requires task, episode, and outcome time")
        try:
            timestamp = float(stamp)
        except (TypeError, ValueError) as exc:
            raise ValueError("outcome time must be numeric") from exc
        if not math.isfinite(timestamp):
            raise ValueError("outcome time must be finite")
        key = str(task)
        groups.setdefault(key, []).append(ex)
        group_time[key] = max(timestamp, group_time.get(key, timestamp))
    if len(groups) < 2:
        raise ValueError("at least two independent task groups are required")

    ordered = sorted(groups, key=lambda key: (group_time[key], key))
    test_groups = max(1, math.ceil(len(ordered) * float(split)))
    test_groups = min(test_groups, len(ordered) - 1)
    test_keys = set(ordered[-test_groups:])
    train_ex = [ex for key in ordered if key not in test_keys for ex in groups[key]]
    test_ex = [ex for key in ordered if key in test_keys for ex in groups[key]]
    return train_ex, test_ex


@dataclass(frozen=True)
class PairedVerifierEvidence:
    """Task-paired confirmation evidence for one frozen challenger.

    Scores are macro-averaged across tasks, so a verbose trajectory cannot
    manufacture sample size. ``quality`` is bounded task accuracy ``1-MAE``;
    raw MSE and clipped-probability Brier loss provide independent calibration
    non-regression guards. Bounds use paired task deltas throughout.
    """

    samples: int
    cohort_sha256: str
    incumbent_quality: float
    challenger_quality: float
    quality_delta: float
    quality_lcb: float
    incumbent_mse: float
    challenger_mse: float
    mse_delta_ucb: float
    incumbent_brier: float
    challenger_brier: float
    brier_delta_ucb: float
    quality_ok: bool
    mse_ok: bool
    brier_ok: bool

    @property
    def promotable(self) -> bool:
        return self.quality_ok and self.mse_ok and self.brier_ok


def freeze_confirmation_anchor(rows: list[dict]) -> tuple[list[dict], str]:
    """Deep-freeze and digest the exact temporal rows used by both heads."""
    canonical_rows: list[dict] = []
    for row in rows:
        # JSON is the artifact/provenance interchange format. Round-tripping
        # here detaches the confirmation set from any caller-owned dictionaries
        # and rejects non-finite values before either model sees the cohort.
        try:
            encoded = json.dumps(
                row, sort_keys=True, separators=(",", ":"), allow_nan=False,
            )
            frozen = json.loads(encoded)
        except (TypeError, ValueError) as exc:
            raise ValueError("confirmation row is not canonical finite JSON") from exc
        if not isinstance(frozen, dict):
            raise ValueError("confirmation row must be an object")
        canonical_rows.append(frozen)
    canonical_rows.sort(key=lambda row: json.dumps(
        row, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ))
    payload = json.dumps(
        {"protocol": "paired-task-v1", "rows": canonical_rows},
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return canonical_rows, hashlib.sha256(payload).hexdigest()


def _task_promise_metrics(
    head: LinearHead, rows: list[dict],
) -> dict[str, tuple[float, float, float]]:
    accumulators: dict[str, list[float]] = {}
    for row in rows:
        task = row.get("task_id", row.get("goal_id"))
        target = _target(row)[0]
        if task is None or target is None or not 0.0 <= target <= 1.0:
            raise ValueError("paired verifier evidence requires bounded task labels")
        weight = _weight(row)
        if weight <= 0.0:
            continue
        try:
            prediction = float(head.promise(list(row["features"])))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("verifier produced no finite paired prediction") from exc
        if not math.isfinite(prediction):
            raise ValueError("verifier produced no finite paired prediction")
        probability = min(1.0, max(0.0, prediction))
        quality = 1.0 - abs(probability - target)
        raw_squared_error = (prediction - target) ** 2
        brier = (probability - target) ** 2
        values = accumulators.setdefault(str(task), [0.0, 0.0, 0.0, 0.0])
        values[0] += weight
        values[1] += weight * quality
        values[2] += weight * raw_squared_error
        values[3] += weight * brier
    if not accumulators:
        raise ValueError("paired verifier evidence requires independent task groups")
    metrics: dict[str, tuple[float, float, float]] = {}
    for task, values in accumulators.items():
        denominator = values[0]
        if denominator <= 0.0:
            raise ValueError("paired verifier task has no positive evidence weight")
        metrics[task] = (
            values[1] / denominator,
            values[2] / denominator,
            values[3] / denominator,
        )
    return metrics


def _paired_mean_bound(
    deltas: list[float], *, confidence_z: float, lower: bool,
) -> tuple[float, float]:
    if len(deltas) < 2:
        raise ValueError("paired bounds require at least two independent tasks")
    if (not isinstance(confidence_z, (int, float))
            or isinstance(confidence_z, bool)
            or not math.isfinite(float(confidence_z))
            or float(confidence_z) <= 0.0):
        raise ValueError("confidence_z must be a positive finite number")
    mean = sum(deltas) / len(deltas)
    variance = sum((value - mean) ** 2 for value in deltas) / (len(deltas) - 1)
    error = float(confidence_z) * math.sqrt(max(0.0, variance) / len(deltas))
    return mean, mean - error if lower else mean + error


def compare_verifiers(
    incumbent: LinearHead, challenger: LinearHead, confirmation_rows: list[dict],
    *, cohort_sha256: str, margin: float = 0.0, confidence_z: float = 1.96,
    mse_tolerance: float = 0.0, brier_tolerance: float = 0.0,
) -> PairedVerifierEvidence:
    """Compare both heads on the same frozen tasks with paired uncertainty."""
    for name, value in (
        ("margin", margin), ("mse_tolerance", mse_tolerance),
        ("brier_tolerance", brier_tolerance),
    ):
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not math.isfinite(float(value)) or float(value) < 0.0):
            raise ValueError(f"{name} must be a non-negative finite number")
    if (not isinstance(cohort_sha256, str) or len(cohort_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in cohort_sha256)):
        raise ValueError("cohort_sha256 must be a lowercase SHA-256 digest")

    incumbent_metrics = _task_promise_metrics(incumbent, confirmation_rows)
    challenger_metrics = _task_promise_metrics(challenger, confirmation_rows)
    task_ids = sorted(incumbent_metrics)
    if set(task_ids) != set(challenger_metrics):
        raise ValueError("incumbent and challenger task cohorts differ")

    quality_delta, quality_lcb = _paired_mean_bound(
        [challenger_metrics[task][0] - incumbent_metrics[task][0]
         for task in task_ids],
        confidence_z=confidence_z, lower=True,
    )
    _mse_delta, mse_ucb = _paired_mean_bound(
        [challenger_metrics[task][1] - incumbent_metrics[task][1]
         for task in task_ids],
        confidence_z=confidence_z, lower=False,
    )
    _brier_delta, brier_ucb = _paired_mean_bound(
        [challenger_metrics[task][2] - incumbent_metrics[task][2]
         for task in task_ids],
        confidence_z=confidence_z, lower=False,
    )

    def mean_at(index: int, metrics: dict[str, tuple[float, float, float]]) -> float:
        return sum(metrics[task][index] for task in task_ids) / len(task_ids)

    return PairedVerifierEvidence(
        samples=len(task_ids), cohort_sha256=cohort_sha256,
        incumbent_quality=mean_at(0, incumbent_metrics),
        challenger_quality=mean_at(0, challenger_metrics),
        quality_delta=quality_delta,
        quality_lcb=max(-1.0, min(1.0, quality_lcb)),
        incumbent_mse=mean_at(1, incumbent_metrics),
        challenger_mse=mean_at(1, challenger_metrics),
        mse_delta_ucb=mse_ucb,
        incumbent_brier=mean_at(2, incumbent_metrics),
        challenger_brier=mean_at(2, challenger_metrics),
        brier_delta_ucb=brier_ucb,
        quality_ok=quality_lcb > float(margin),
        mse_ok=mse_ucb <= float(mse_tolerance),
        brier_ok=brier_ucb <= float(brier_tolerance),
    )


def train_and_evaluate(examples: list[dict], *, split: float = 0.3, seed: int = 0) -> dict:
    """Train and report held-out accuracy without trajectory leakage.

    Outcome-supervised examples (identified by provenance metadata) always use
    the group/temporal split. Legacy direct callers that provide no identity
    metadata retain the deterministic shuffled split for compatibility. A mixed
    corpus is rejected because silently discarding provenance would invalidate
    the held-out result.
    """
    ex = list(examples)
    has_identity = [
        any(key in row for key in ("task_id", "goal_id", "episode_id",
                                   "outcome_verified_at"))
        for row in ex
    ]
    if any(has_identity):
        if not all(has_identity):
            raise ValueError("cannot mix provenance-aware and legacy PRM examples")
        train_ex, test_ex = group_temporal_split(ex, split=split)
        split_mode = "group_temporal"
    else:
        rng = random.Random(seed)
        rng.shuffle(ex)
        cut = max(1, int(len(ex) * (1.0 - split))) if len(ex) > 1 else 1
        train_ex, test_ex = ex[:cut], ex[cut:] or ex[:1]
        split_mode = "legacy_random"
    train_groups = len({str(row.get("task_id", row.get("goal_id"))) for row in train_ex})
    test_groups = len({str(row.get("task_id", row.get("goal_id"))) for row in test_ex})
    head = train(train_ex, seed=seed)
    return {
        "head": head,
        "n": len(ex),
        "train_n": len(train_ex),
        "test_n": len(test_ex),
        "train_groups": train_groups,
        "test_groups": test_groups,
        "split_mode": split_mode,
        "train_mse": round(mse(head, train_ex), 6),
        "test_mse": round(mse(head, test_ex), 6),
        "baseline_test_mse": round(baseline_mse(train_ex, test_ex), 6),
        "discrimination": round(discrimination(head, test_ex), 6),
    }


def train_and_propose(
    store, *, controller=None,
    deployment: VerifierArtifactDeployment | None = None,
    split: float = 0.3, seed: int = 0, min_examples: int = 20,
    trusted_labels=None, trusted_outcome_sources: frozenset[str] | None = None,
    approve=None, confidence_z: float = 1.96,
    mse_tolerance: float = 0.0, brier_tolerance: float = 0.0,
):
    """Train, stage, govern, and activate a serving-compatible verifier head.

    Builds examples from the trajectory store, trains a head on CPU, and routes
    it through the dedicated ``evaluator`` rung. The deployed incumbent and
    challenger are scored task-by-task on the exact same frozen newest temporal
    cohort. Promotion requires the paired quality lower confidence bound to
    clear the configured margin while paired MSE and Brier upper bounds do not
    regress. An absent artifact is represented explicitly by the trivial zero
    head; no synthetic ``baseline_score=0`` shortcut is used. Returns the
    controller verdict, or None when there isn't enough trustworthy data or no
    deployment path was supplied. A candidate is content-addressed and fully
    validated before the gate. The controller then
    durably PREPAREs the exact before/after revisions, the artifact is atomically
    activated, and COMMIT is journaled while the artifact lock remains held.
    Crash-left PREPAREs are reconciled by
    :meth:`VerifierArtifactDeployment.recover`. ``approve``, when supplied,
    receives the immutable :class:`approval_signing.ApprovalRequest` and returns
    an external signature. This lets a human-authorized update cross the default
    policy ceiling without putting a signing key in the agent process.
    """
    from .self_improvement import Candidate, GateResult, Verdict, shared
    from .self_improvement_runner import build_prm_examples

    active_controller = controller if controller is not None else shared()

    examples = build_prm_examples(
        store, trusted_labels=trusted_labels,
        trusted_outcome_sources=trusted_outcome_sources,
    )
    if len(examples) < min_examples:
        return None
    if (deployment is None
            or not callable(getattr(deployment, "stage", None))
            or not callable(getattr(deployment, "snapshot_for_evaluation", None))
            or not callable(getattr(deployment, "consume_confirmation", None))):
        return None
    try:
        train_examples, confirmation_examples = group_temporal_split(
            examples, split=split,
        )
        confirmation_examples, cohort_sha256 = freeze_confirmation_anchor(
            confirmation_examples,
        )
        incumbent, evaluated_before, incumbent_source = (
            deployment.snapshot_for_evaluation(active_controller)
        )
        challenger = train(train_examples, seed=seed)
    except (OSError, TypeError, ValueError, VerifierRecoveryRequired):
        # One task with many steps is not independent evidence. Hold rather than
        # leaking that task into both train and confirmation, or evaluating an
        # incumbent whose authority cannot be proven.
        return None
    try:
        activation = deployment.stage(challenger)
        if not all(callable(getattr(activation, name, None)) for name in (
            "locked", "_activate_locked", "_current_revision_locked", "rollback",
            "evaluation_head",
        )) or not hasattr(activation, "after_revision"):
            return None
        deployment.consume_confirmation(
            active_controller, cohort_sha256=cohort_sha256,
            before=evaluated_before, after=activation.after_revision,
        )
        # Score the immutable digest-bound staged bytes, not a mutable
        # trainer-side object or a validate-then-read path race.
        staged_challenger = activation.evaluation_head()
        evidence = compare_verifiers(
            incumbent, staged_challenger, confirmation_examples,
            cohort_sha256=cohort_sha256,
            margin=active_controller.min_improvement,
            confidence_z=confidence_z,
            mse_tolerance=mse_tolerance,
            brier_tolerance=brier_tolerance,
        )
    except (OSError, TypeError, ValueError, VerifierRecoveryRequired):
        log.warning("verifier staging or paired evaluation failed", exc_info=True)
        return None

    summary = (
        f"verifier update: paired confirmation on {evidence.samples} independent tasks "
        f"(quality {evidence.challenger_quality:.6f} vs incumbent "
        f"{evidence.incumbent_quality:.6f}; LCB {evidence.quality_lcb:.6f}; "
        f"MSE delta UCB {evidence.mse_delta_ucb:.6f}; Brier delta UCB "
        f"{evidence.brier_delta_ucb:.6f}; "
        f"artifact {activation.artifact.version})"
    )
    after = activation.after_revision
    candidate = Candidate(
        # A verifier reshapes the learning signal for every downstream policy;
        # route it through the dedicated rung above the default autonomous
        # policy ceiling instead of disguising it as an ordinary policy tweak.
        rung="evaluator",
        summary=summary,
        baseline_score=evidence.incumbent_quality,
        candidate_score=evidence.challenger_quality,
        samples=evidence.samples,
        effect_ci_low=evidence.quality_lcb,
        rollback=activation.rollback,
        capability_widens=False,
        payload={
            "artifact_before": evaluated_before.to_dict(),
            "artifact_after": after.to_dict(),
            "confirmation_cohort_sha256": evidence.cohort_sha256,
        },
        provenance={
            "kind": "verifier",
            "evidence_protocol": "paired-task-v1",
            "incumbent_source": incumbent_source,
            "incumbent_sha256": evaluated_before.sha256,
            "artifact_sha256": activation.artifact.sha256,
            "artifact_version": activation.artifact.version,
            "confirmation_cohort_sha256": evidence.cohort_sha256,
            "confirmation_tasks": evidence.samples,
            "incumbent_quality": evidence.incumbent_quality,
            "challenger_quality": evidence.challenger_quality,
            "quality_delta": evidence.quality_delta,
            "quality_lcb": evidence.quality_lcb,
            "incumbent_mse": evidence.incumbent_mse,
            "challenger_mse": evidence.challenger_mse,
            "mse_delta_ucb": evidence.mse_delta_ucb,
            "incumbent_brier": evidence.incumbent_brier,
            "challenger_brier": evidence.challenger_brier,
            "brier_delta_ucb": evidence.brier_delta_ucb,
        },
    )
    paired_gates = (
        GateResult(
            "paired_quality", evidence.quality_ok,
            "" if evidence.quality_ok else (
                f"paired quality LCB {evidence.quality_lcb:.6f} did not clear "
                f"margin {float(active_controller.min_improvement):.6f}"
            ),
        ),
        GateResult(
            "mse_non_regression", evidence.mse_ok,
            "" if evidence.mse_ok else (
                f"paired MSE delta UCB {evidence.mse_delta_ucb:.6f} exceeded "
                f"tolerance {float(mse_tolerance):.6f}"
            ),
        ),
        GateResult(
            "brier_non_regression", evidence.brier_ok,
            "" if evidence.brier_ok else (
                f"paired Brier delta UCB {evidence.brier_delta_ucb:.6f} exceeded "
                f"tolerance {float(brier_tolerance):.6f}"
            ),
        ),
    )
    if not evidence.promotable:
        reason = next(gate.reason for gate in paired_gates if not gate.ok)
        return Verdict(
            candidate.id, candidate.rung, False, paired_gates, reason,
        )
    if approve is not None:
        try:
            from .approval_signing import ApprovalRequest

            request = ApprovalRequest.for_candidate(candidate)
            signature = approve(request)
            if signature:
                candidate.approval_signature = str(signature)
                candidate.payload_sha256 = request.payload_sha256
        except Exception:
            # Approval transport is outside the learning trust boundary. Any
            # outage or malformed response leaves the candidate unsigned, so
            # the evaluator-above-policy human gate refuses it.
            log.warning("verifier approval request failed", exc_info=True)
    with activation.locked():
        before = activation._current_revision_locked()
        if before != evaluated_before:
            reason = "active verifier changed after paired confirmation"
            return Verdict(
                candidate.id, candidate.rung, False,
                (*paired_gates, GateResult("deployment", False, reason)),
                reason,
            )
        preparation = active_controller.prepare_promotion(
            candidate, before=before, after=after,
        )
        if not preparation.ok:
            return preparation.verdict
        if preparation.committed:
            observed = activation._current_revision_locked()
            if observed == after:
                return preparation.verdict
            reason = "committed verifier receipt does not match active artifact"
            return Verdict(
                preparation.verdict.candidate_id, preparation.verdict.rung, False,
                (*preparation.verdict.gates,
                 GateResult("deployment", False, reason)),
                reason, approver_id=preparation.verdict.approver_id,
            )

        # PREPARE is durable, but no serving artifact has changed yet. A HALT
        # armed during evaluation/approval must win immediately before the
        # atomic activation; abort against the exact observed pre-state.
        try:
            from .learning_guard import check_learning_halt
            check_learning_halt("verifier_head", "before-activation")
        except Exception:
            observed = activation._current_revision_locked()
            log.warning("verifier activation refused by learning safety boundary")
            return active_controller.abort_prepared(
                preparation,
                artifact=observed,
                reason="learning safety check refused verifier activation",
            )

        authorization = active_controller.authorize_prepared(
            preparation,
            artifact=before,
        )
        if not authorization.ok:
            return authorization

        try:
            activation._activate_locked(expected_before=before)
        except Exception:
            # If atomic activation left the exact after-state live, finish the
            # commit. Exact before safely aborts. Any third state remains in
            # doubt and blocks later promotions until recovery resolves it.
            observed = activation._current_revision_locked()
            if observed == after:
                return active_controller.commit_prepared(
                    preparation, artifact=observed,
                )
            log.warning("verifier artifact activation failed", exc_info=True)
            return active_controller.abort_prepared(
                preparation, artifact=observed,
                reason="verifier artifact activation failed",
            )

        observed = activation._current_revision_locked()
        return active_controller.commit_prepared(preparation, artifact=observed)


__all__ = [
    "LinearHead", "StagedVerifierArtifact", "VerifierRecoveryRequired",
    "VerifierActivation", "VerifierArtifactDeployment", "PairedVerifierEvidence",
    "train", "mse", "baseline_mse", "discrimination", "group_temporal_split",
    "freeze_confirmation_anchor", "compare_verifiers", "train_and_evaluate",
    "train_and_propose",
]
