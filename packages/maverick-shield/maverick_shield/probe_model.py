"""Trained-classifier scoring seam for the cheap-probe tier.

The Constitutional-v2 cheap probe (:mod:`maverick_shield.cascade`) is purely
heuristic: hand-tuned regex/unicode signals. That is a strong recall floor but
there was no way to put a *trained* classifier into the first pass -- the gap
between "heuristic shield" and "trained safety model".

This adds that seam **safely**. A model is a set of linear weights over the
probe's own named features, loaded from a plain JSON artifact -- no pickle, so
loading an operator-supplied model can't execute code (unacceptable in a safety
component). An operator trains a logistic-regression / linear classifier offline
on labelled jailbreak data and exports::

    {"bias": -1.2, "weights": {"regex_hit": 2.3, "non_ascii_ratio": 1.1, ...},
     "threshold": 0.5}

``LinearProbeModel.score(text)`` returns a calibrated probability in ``[0, 1]``.
The cascade ensembles it with the heuristic by taking the MAX, so adding a model
can only *raise* recall, never weaken the existing floor. Default OFF: with no
``[shield] probe_model`` / ``MAVERICK_SHIELD_PROBE_MODEL`` configured, the probe
behaves exactly as before.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import stat
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, runtime_checkable

log = logging.getLogger(__name__)
_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_MAX_WEIGHTS = 65_536
_REFRESH_SECONDS = 5.0
_FAILED_REFRESH_SECONDS = 2.0
_MAX_CACHE_ENTRIES = 32
FEATURE_SCHEMA = "cheap-probe-features-v1"

# Reuse the cheap probe's signal regexes so a trained model scores over the same
# features the heuristic sees (kept import-light: compiled here, mirrors cascade).
_RX_REGEX = None  # lazily bound from cascade to avoid an import cycle at import time
_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")
_INVISIBLE_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u206f]")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HEX_RE = re.compile(r"\\x[0-9a-fA-F]{2}.{0,10}\\x[0-9a-fA-F]{2}")


def _probe_regex():
    global _RX_REGEX
    if _RX_REGEX is None:
        from .cascade import _PROBE_REGEX
        _RX_REGEX = _PROBE_REGEX
    return _RX_REGEX


def probe_features(text: str, *, ngram_buckets: int = 0,
                   ngram_sizes: tuple[int, ...] = (3, 4, 5)) -> dict[str, float]:
    """Numeric features for a text, the model's input vector.

    Binary signals mirror the heuristic probe; ``non_ascii_ratio`` and
    ``log_length`` give the model continuous signal the heuristic discretizes.
    Stable feature names are the model's contract.

    When ``ngram_buckets > 0`` the vector is ADDITIVELY extended with hashed
    character n-gram features ``ng:<bucket>`` (TF-normalised), giving a model
    lexical content the 7 hand-named signals can't carry. The hashing is
    deterministic (blake2b, not the randomised built-in ``hash``) so train and
    inference agree across processes. ``ngram_buckets = 0`` (the default) yields
    exactly the original 7 features, so every existing model is unaffected."""
    if not text:
        return {}
    n = len(text)
    non_ascii = sum(1 for c in text if ord(c) > 127)
    feats = {
        "regex_hit": 1.0 if _probe_regex().search(text.lower()) else 0.0,
        "unicode_tag": 1.0 if _TAG_RE.search(text) else 0.0,
        "zero_width": 1.0 if _INVISIBLE_RE.search(text) else 0.0,
        "base64_blob": 1.0 if _B64_RE.search(text) else 0.0,
        "hex_escape": 1.0 if _HEX_RE.search(text) else 0.0,
        "non_ascii_ratio": non_ascii / max(n, 1),
        "log_length": math.log10(n + 1),
    }
    if ngram_buckets > 0:
        _add_ngram_features(feats, text.lower(), ngram_buckets, ngram_sizes)
    return feats


def _ngram_bucket(gram: str, buckets: int) -> int:
    """Deterministic, process-stable hash of an n-gram into ``[0, buckets)``."""
    digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % buckets


def _add_ngram_features(feats: dict[str, float], text: str, buckets: int,
                        sizes: tuple[int, ...]) -> None:
    grams = [text[i:i + s] for s in sizes for i in range(len(text) - s + 1)]
    if not grams:
        return
    inc = 1.0 / len(grams)  # TF-normalise so values stay bounded in [0, 1]
    for g in grams:
        key = f"ng:{_ngram_bucket(g, buckets)}"
        feats[key] = feats.get(key, 0.0) + inc


def _sigmoid(z: float) -> float:
    # Numerically stable logistic.
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


@runtime_checkable
class ProbeModel(Protocol):
    """Anything that scores a text's jailbreak likelihood in ``[0, 1]``."""

    def score(self, text: str) -> float: ...


@dataclass(frozen=True)
class LinearProbeModel:
    """A linear/logistic classifier over :func:`probe_features`.

    ``score = sigmoid(bias + Σ weights[f] * feature[f])``. Unknown feature
    names in ``weights`` are ignored; missing features count as 0. ``threshold``
    is advisory metadata (the cascade uses the raw probability)."""

    bias: float = 0.0
    weights: Mapping[str, float] | None = None
    threshold: float = 0.5
    # n-gram feature config; 0 = the original 7-feature contract (back-compat).
    ngram_buckets: int = 0
    ngram_sizes: tuple[int, ...] = (3, 4, 5)
    schema_version: int = 1
    artifact_version: str = "unversioned"

    def __post_init__(self) -> None:
        weights = self.weights if self.weights is not None else {}
        if not isinstance(weights, Mapping) or len(weights) > _MAX_WEIGHTS:
            raise ValueError("probe model weights must be a bounded object")
        if any(not isinstance(key, str) or len(key) > 128 for key in weights):
            raise ValueError("probe model feature names are invalid")
        clean = {key: _finite_number(value) for key, value in weights.items()}
        bias = _finite_number(self.bias)
        threshold = _finite_number(self.threshold)
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("probe model threshold must be in [0,1]")
        if (isinstance(self.ngram_buckets, bool) or not isinstance(self.ngram_buckets, int)
                or not 0 <= self.ngram_buckets <= 65_536):
            raise ValueError("probe model ngram bucket count is invalid")
        sizes = self.ngram_sizes
        if (not isinstance(sizes, (tuple, list)) or not 1 <= len(sizes) <= 8
                or any(isinstance(size, bool) or not isinstance(size, int)
                       or not 1 <= size <= 32 for size in sizes)):
            raise ValueError("probe model ngram sizes are invalid")
        if type(self.schema_version) is not int or self.schema_version not in (0, 1):
            raise ValueError("unsupported probe model schema")
        if (not isinstance(self.artifact_version, str)
                or not 1 <= len(self.artifact_version) <= 128
                or any(ord(char) < 32 for char in self.artifact_version)):
            raise ValueError("invalid probe model artifact version")
        object.__setattr__(self, "weights", MappingProxyType(clean))
        object.__setattr__(self, "bias", bias)
        object.__setattr__(self, "threshold", threshold)
        object.__setattr__(self, "ngram_sizes", tuple(sizes))

    def score(self, text: str) -> float:
        feats = probe_features(text, ngram_buckets=self.ngram_buckets,
                               ngram_sizes=self.ngram_sizes)
        z = float(self.bias)
        for name, w in (self.weights or {}).items():
            z += float(w) * feats.get(name, 0.0)
        return _sigmoid(z)

    @classmethod
    def from_dict(cls, data: dict) -> LinearProbeModel:
        if not isinstance(data, dict):
            raise ValueError("probe model must be a JSON object")
        weights = data.get("weights", {})
        if not isinstance(weights, dict):
            raise ValueError("probe model 'weights' must be an object")
        if data.get("feature_schema", FEATURE_SCHEMA) != FEATURE_SCHEMA:
            raise ValueError("unsupported probe model feature schema")
        return cls(
            bias=data.get("bias", 0.0), weights=weights,
            threshold=data.get("threshold", 0.5),
            ngram_buckets=data.get("ngram_buckets", 0),
            ngram_sizes=data.get("ngram_sizes", (3, 4, 5)),
            schema_version=data.get("schema_version", 0),
            artifact_version=data.get("artifact_version", "unversioned"),
        )


def _finite_number(value) -> float:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or abs(value) > 1_000_000):
        raise ValueError("probe model numbers must be finite and bounded")
    return float(value)


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate model JSON field")
        result[key] = value
    return result


def _load_artifact(path: str) -> tuple[LinearProbeModel | None, str, str]:
    """Validate one bounded byte snapshot before publishing its digest/model."""
    digest = ""
    try:
        if not Path(path).is_file():
            return None, "", "missing_artifact"
        with Path(path).open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                return None, "", "rejected_artifact"
            raw = stream.read(_MAX_ARTIFACT_BYTES + 1)
            after = os.fstat(stream.fileno())
        if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            return None, "", "artifact_changed_during_read"
        if len(raw) > _MAX_ARTIFACT_BYTES:
            return None, "", "artifact_too_large"
        digest = hashlib.sha256(raw).hexdigest()
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields)
        return LinearProbeModel.from_dict(data), digest, ""
    except FileNotFoundError:
        return None, "", "missing_artifact"
    except (OSError, UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
        return None, digest, "rejected_artifact"


def load_probe_model(path: str | Path) -> LinearProbeModel | None:
    """Load a JSON linear-model artifact. Returns ``None`` (fail-open) on a
    missing path or malformed file -- a broken model must not break scanning."""
    model, _digest, reason = _load_artifact(str(Path(path).expanduser()))
    if reason:
        log.warning("shield probe_model: %s", reason)
    return model


_cache_lock = threading.Lock()
@dataclass(frozen=True)
class _CacheEntry:
    model: LinearProbeModel | None
    digest: str
    next_refresh: float
    state: str
    reason: str = ""
    rejected_digest: str = ""


_cached: OrderedDict[tuple[str, str], _CacheEntry] = OrderedDict()


def _configuration_key() -> tuple[str, str] | None:
    """Resolve each tenant independently; a config failure cannot reuse another."""
    path = os.environ.get("MAVERICK_SHIELD_PROBE_MODEL", "").strip()
    try:
        from maverick.paths import current_tenant_id
        tenant = current_tenant_id() or ""
    except ImportError:  # standalone shield without the optional core package
        tenant = ""
    except Exception:
        return None
    if not path:
        try:
            from maverick.config import load_config
            path = str((load_config() or {}).get("shield", {}).get("probe_model", "")).strip()
        except Exception:  # core/config is optional
            return None
    if not path:
        return None
    try:
        return tenant, str(Path(path).expanduser().resolve())
    except (OSError, RuntimeError, ValueError):
        return None


def _configured_entry() -> _CacheEntry | None:
    key = _configuration_key()
    if key is None:
        return None
    with _cache_lock:
        now = time.monotonic()
        entry = _cached.get(key)
        if entry is not None and now < entry.next_refresh:
            _cached.move_to_end(key)
            return entry
        model, digest, reason = _load_artifact(key[1])
        if model is not None:
            # Publication is atomic and old objects are immutable, including
            # the weights mapping. Filesystem mtime is never artifact identity.
            entry = _CacheEntry(model, digest, now + _REFRESH_SECONDS, "active")
        else:
            previous = entry.model if entry else None
            entry = _CacheEntry(
                previous, entry.digest if entry else "",
                now + _FAILED_REFRESH_SECONDS,
                "stale_rejected" if previous is not None else "unavailable",
                reason, digest)
            log.warning("shield probe_model: %s; state=%s", reason, entry.state)
        _cached[key] = entry
        _cached.move_to_end(key)
        while len(_cached) > _MAX_CACHE_ENTRIES:
            _cached.popitem(last=False)
        return entry


def configured_probe_model() -> LinearProbeModel | None:
    """The operator-configured probe model, or ``None`` when unset.

    Path from ``MAVERICK_SHIELD_PROBE_MODEL`` or ``[shield] probe_model``.
    A tenant/path cache refreshes bounded bytes at most every five seconds.
    Failed loads retry after two seconds; a last known good model is retained
    with explicit stale/rejected status. Configuring another path never reuses
    the previous path's model. Built-in rules always remain the floor."""
    entry = _configured_entry()
    return entry.model if entry else None


def configured_probe_status() -> dict:
    """Operator-readable identity and reload state, without filesystem paths."""
    entry = _configured_entry()
    return {
        "state": entry.state if entry else "disabled",
        "active_sha256": entry.digest if entry else "",
        "schema_version": entry.model.schema_version if entry and entry.model else None,
        "artifact_version": entry.model.artifact_version if entry and entry.model else None,
        "feature_schema": FEATURE_SCHEMA,
        "reload_reason": entry.reason if entry else "",
        "rejected_sha256": entry.rejected_digest if entry else "",
        "refresh_in_seconds": max(0.0, entry.next_refresh - time.monotonic()) if entry else 0.0,
    }


def _reset_cache() -> None:
    """Test hook: drop the cached model so a new path/file is re-read."""
    with _cache_lock:
        _cached.clear()


__all__ = [
    "ProbeModel", "LinearProbeModel", "probe_features",
    "load_probe_model", "configured_probe_model", "configured_probe_status",
]
