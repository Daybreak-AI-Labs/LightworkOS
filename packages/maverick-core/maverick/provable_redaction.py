"""Provable redaction.

The secret/PII redactors (:mod:`maverick.safety.secret_detector` /
:mod:`maverick.safety.pii_detector`) replace what they find in a single pass.
"Provable" adds the guarantee a compliance reviewer actually wants: redact to a
**fixpoint** and then *re-scan the output* to prove nothing sensitive survived.

A single pass can leave residue — overlapping/adjacent matches, or a value
only exposed once another span around it is replaced. So this iterates
redaction until a pass finds nothing left (the proof), bounded by
``max_passes``; if the bound is hit with residue still present the result is
explicitly **not proven** and the residual labels are returned, rather than
quietly handing back a partly-redacted string.

Composes the existing detectors — no new detection logic — so it inherits
their coverage. Deterministic and offline.
"""
from __future__ import annotations

from dataclasses import dataclass


def _scan_all(text: str) -> list[str]:
    """Labels of every sensitive span (secrets + PII) in ``text``. ``[]`` == clean."""
    from .safety import pii_detector, secret_detector
    labels = [f"secret:{m.name}" for m in secret_detector.scan(text)]
    labels += [f"pii:{m.kind}" for m in pii_detector.scan(text)]
    return labels


def _redact_once(text: str) -> str:
    from .safety import pii_detector, secret_detector
    out, _ = secret_detector.redact(text)
    out, _ = pii_detector.redact(out)
    return out


@dataclass(frozen=True)
class RedactionProof:
    redacted: str
    passes: int
    residual: list[str]   # sensitive labels still present (empty == proven)

    @property
    def proven(self) -> bool:
        return not self.residual


def redact_proven(text: str, *, max_passes: int = 5) -> RedactionProof:
    """Redact ``text`` to a fixpoint and prove the output re-scans clean.

    Returns a :class:`RedactionProof`; ``proven`` is True iff a redaction pass
    reached a state with no detectable secrets/PII within ``max_passes``.
    """
    if not text:
        return RedactionProof(text, 0, [])
    cur = text
    passes = 0
    while passes < max_passes:
        passes += 1
        cur = _redact_once(cur)
        if not _scan_all(cur):       # fixpoint reached: provably clean
            return RedactionProof(cur, passes, [])
    return RedactionProof(cur, passes, _scan_all(cur))


def verify_redacted(text: str) -> list[str]:
    """Sensitive labels still present in an (already-redacted) ``text``.

    ``[]`` means provably clean; a non-empty list is the redaction gap.
    """
    return _scan_all(text)


__all__ = ["RedactionProof", "redact_proven", "verify_redacted"]
