"""Neutral projection shared by deterministic anomaly detectors.

The platform's run-behavior detector and finance transaction detector have
different evidence semantics.  This small envelope lets workflows and sinks
consume both without forcing either detector into the other's data model.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

SIGNAL_SCHEMA = "lightwork.anomaly-signal.v1"
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def _bounded(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ValueError(f"{label} must contain 1 to {limit} characters")
    return text


@dataclass(frozen=True)
class AnomalySignal:
    """Stable common envelope; detector-native evidence remains authoritative."""

    detector_id: str
    detector_version: str
    kind: str
    severity: str
    subject_ref: str
    detail: str
    evidence_sha256s: tuple[str, ...] = ()
    schema: str = SIGNAL_SCHEMA

    def __post_init__(self) -> None:
        for name in ("detector_id", "detector_version", "kind"):
            value = _bounded(getattr(self, name), name, 128)
            if _TOKEN.fullmatch(value) is None:
                raise ValueError(f"{name} contains unsupported characters")
            object.__setattr__(self, name, value)
        severity = _bounded(self.severity, "severity", 16).lower()
        if severity not in _SEVERITIES:
            raise ValueError("severity is invalid")
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "subject_ref", _bounded(self.subject_ref, "subject_ref", 512))
        object.__setattr__(self, "detail", _bounded(self.detail, "detail", 4_000))
        digests = tuple(str(value or "").strip().lower() for value in self.evidence_sha256s)
        if len(digests) > 100 or any(_DIGEST.fullmatch(value) is None for value in digests):
            raise ValueError("evidence_sha256s must contain at most 100 SHA-256 digests")
        object.__setattr__(self, "evidence_sha256s", tuple(sorted(set(digests))))
        if self.schema != SIGNAL_SCHEMA:
            raise ValueError("anomaly signal schema is unsupported")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "kind": self.kind,
            "severity": self.severity,
            "subject_ref": self.subject_ref,
            "detail": self.detail,
            "evidence_sha256s": list(self.evidence_sha256s),
        }

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


__all__ = ["AnomalySignal", "SIGNAL_SCHEMA"]
