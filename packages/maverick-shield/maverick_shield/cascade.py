"""Constitutional Classifier v2 cascaded scan tier.

Anthropic's Jan 2026 paper (Constitutional Classifiers v2) ships a
two-tier defense: a CHEAP first-pass classifier flags candidates, and
only flagged texts get the EXPENSIVE second-pass classifier. The cheap
pass uses lightweight features (regex hits, n-gram heuristics, length,
unicode anomalies); the expensive pass is an LLM-based judge. Cut
jailbreak success 86% -> 4.4% with much lower compute than v1.

This module wraps the existing Shield's scan_* methods with that
cascade. When `MAVERICK_CASCADE_SHIELD=1` or ``[safety] cascade = true``,
every call goes through the cheap probe first; ONLY on probe-flagged texts
do we invoke the LLM-based deep scan. Default OFF (back-compat).

The expensive scanner is pluggable: pass a callable returning
ShieldVerdict at construction. When None, deep-pass falls back to the
existing builtin/Shield rules. The kernel's run path
(``maverick.orchestrator._build_shield``) passes the model-based judge in
``maverick.safety.shield_judge``.
"""
from __future__ import annotations

import logging
import os
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger(__name__)


# Cheap-pass signals. These are heuristics tuned to maximize RECALL
# (false positive is fine -- the expensive pass filters); they should
# NEVER be the sole defense.
_PROBE_REGEX = re.compile(
    r"""
    (ignore\s+(?:\w+\s+){0,3}(instructions?|prompts?|directives?))
    | (system\s*(prompt|message)\s*[:=])
    | ((</?system>)|(\[INST\])|(<\|im_start\|>))   # ChatML / Llama markers
    | (rm\s+-rf\s+/(?:\s|$|\*))
    | (curl\s+[^|]+\|\s*(sh|bash|python))
    | (eval\s*\(\s*request|exec\s*\(\s*(stdin|input))
    | (\.env\b|\.aws/credentials|id_rsa\b|\.ssh/id_)
    | (drop\s+table|;\s*drop\s+)
    | (jailbreak|DAN\s+mode|developer\s+mode)
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Unicode tag block U+E0000–U+E007F (steganographic invisible chars).
_TAG_RE = re.compile(r"[\U000E0000-\U000E007F]")
# Zero-width / format chars.
_INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f]")


@dataclass
class ProbeSignal:
    flagged: bool
    score: float
    reasons: list[str]


def cheap_probe(text: str, *, model: object | None = "__configured__") -> ProbeSignal:
    """Constitutional v2-style cheap classifier.

    Returns a ProbeSignal with score in [0,1] and reasons. Threshold for
    "flagged" is 0.3 by default -- intentionally low so we err toward
    sending more texts to the deep scan. The deep scan can still pass.

    When a trained probe model is configured (``[shield] probe_model`` /
    ``MAVERICK_SHIELD_PROBE_MODEL``), its probability is ENSEMBLED with the
    heuristic by taking the max -- so a model can only raise recall, never
    weaken the heuristic floor. Pass ``model=None`` to force heuristics-only,
    or an explicit object exposing ``score(text)`` to override the configured
    one (used in tests).
    """
    if not text:
        return ProbeSignal(flagged=False, score=0.0, reasons=[])

    score = 0.0
    reasons: list[str] = []
    text_l = text.lower()

    # Regex hits.
    m = _PROBE_REGEX.search(text_l)
    if m:
        score += 0.5
        reasons.append(f"pattern: {m.group(0)[:40]}")

    # Unicode tag smuggling.
    if _TAG_RE.search(text):
        score += 0.4
        reasons.append("unicode tag chars")
    if _INVISIBLE_RE.search(text):
        score += 0.2
        reasons.append("zero-width / bidi chars")

    # Heavy obfuscation: very long unbroken non-ASCII run.
    non_ascii = sum(1 for c in text if ord(c) > 127)
    if non_ascii > 100 and non_ascii / max(len(text), 1) > 0.5:
        score += 0.15
        reasons.append("majority non-ASCII")

    # Base64-shaped block of suspicious length.
    if re.search(r"[A-Za-z0-9+/]{200,}={0,2}", text):
        score += 0.15
        reasons.append("base64-shaped large blob")

    # Encoded payload markers: \x.., \u....
    if re.search(r"\\x[0-9a-fA-F]{2}.{0,10}\\x[0-9a-fA-F]{2}", text):
        score += 0.15
        reasons.append("hex-escape payload")

    score = min(score, 1.0)

    # Optional trained-classifier ensemble (max => never weaker than heuristics).
    if model == "__configured__":
        try:
            from .probe_model import configured_probe_model
            model = configured_probe_model()
        except Exception:  # pragma: no cover -- model wiring never breaks the probe
            model = None
    if model is not None:
        try:
            m_score = float(model.score(text))
            if m_score > score:
                reasons.append(f"trained model: {m_score:.2f}")
            score = max(score, min(m_score, 1.0))
        except Exception:  # pragma: no cover -- a bad model must not break scanning
            log.warning("cheap_probe: probe model scoring failed", exc_info=True)

    flagged = score >= 0.3
    return ProbeSignal(flagged=flagged, score=score, reasons=reasons)


@dataclass
class CascadedShield:
    """Wraps the existing Shield in a cheap-then-deep cascade.

    Usage::

        shield = CascadedShield(base=Shield.from_config())
        shield.scan_input(text)   # cheap probe -> base scan if flagged

    `base` is the existing Shield (or any object exposing scan_input /
    scan_tool_call / scan_output). The base scan ALWAYS runs (it is the
    cheap regex floor); the cheap probe only decides whether to additionally
    pay for the optional expensive deep scanner on a base-allowed input. The
    cascade is therefore never weaker than the base it wraps.
    """
    base: object
    deep_threshold: float = 0.3
    deep_scan_input: Callable | None = None
    deep_scan_output: Callable | None = None

    @classmethod
    def from_config(cls) -> CascadedShield:
        from .guard import Shield  # local import to avoid cycle
        return cls(base=Shield.from_config())

    @property
    def backend(self) -> str:
        return f"cascade({getattr(self.base, 'backend', 'unknown')})"

    @property
    def enabled(self) -> bool:
        return getattr(self.base, "enabled", True)

    def _probe(self, text):
        """Run the cheap probe on raw and normalised text.

        The raw pass preserves signals that depend on Unicode smuggling
        characters being present. The normalised pass catches payloads hidden
        with fullwidth/zero-width obfuscation. Never raises: the base scan is
        the security floor, the probe only gates the optional expensive judge.
        """
        try:
            if not isinstance(text, str):
                return ProbeSignal(flagged=False, score=0.0, reasons=[])

            raw_signal = cheap_probe(text)
            normalized = normalize_for_probe(text)
            if normalized == text:
                return raw_signal

            normalized_signal = cheap_probe(normalized)
            reasons = list(dict.fromkeys(raw_signal.reasons + normalized_signal.reasons))
            score = max(raw_signal.score, normalized_signal.score)
            return ProbeSignal(
                flagged=raw_signal.flagged or normalized_signal.flagged,
                score=score,
                reasons=reasons,
            )
        except Exception:  # pragma: no cover - probe must never break the scan
            return ProbeSignal(flagged=False, score=0.0, reasons=[])

    def _cascade(self, text, base_verdict, deep_scan):
        """Combine the base verdict with an optional probe-gated deep scan.

        Invariant: the cascade is NEVER weaker than the base. The base scan
        always runs and a base BLOCK is terminal. The cheap probe only decides
        whether to additionally invoke the expensive deep scanner (LLM judge)
        on inputs the base allowed -- which can only tighten the verdict. The
        previous design short-circuited to ALLOW on a clean probe and skipped
        the base entirely, so enabling the cascade allow-listed attacks the
        base layer blocks. That is fixed here.
        """
        probe = self._probe(text)
        if base_verdict.allowed and deep_scan is not None and (
            probe.flagged or probe.score >= self.deep_threshold
        ):
            verdict = deep_scan(text)
        else:
            verdict = base_verdict
        if probe.reasons and getattr(verdict, "reasons", None) is not None:
            try:
                verdict.reasons = list(verdict.reasons) + [
                    f"cheap-probe: {r}" for r in probe.reasons
                ]
            except Exception:  # pragma: no cover
                pass
        return verdict

    def scan_input(self, text: str):
        return self._cascade(text, self.base.scan_input(text), self.deep_scan_input)

    def scan_tool_call(self, tool_name: str, args: dict):
        # Tool calls always go through the base scanner because the
        # call pattern (tool name + args) is small + structured; no
        # cheap-probe step saves measurable compute.
        return self.base.scan_tool_call(tool_name, args)

    def scan_output(self, text: str, known_prompt: str | None = None):
        # Forward known_prompt to the base scanner so its output-policy
        # regurgitation detector runs (a system-prompt-leak the input-tuned
        # cheap probe cannot flag). The base scan is always the floor;
        # _cascade only lets the optional deep scanner TIGHTEN a base-allowed
        # verdict, so the cascade is never weaker than the base.
        return self._cascade(
            text,
            self.base.scan_output(text, known_prompt=known_prompt),
            self.deep_scan_output,
        )


def cascade_enabled() -> bool:
    """``MAVERICK_CASCADE_SHIELD`` (either way) wins over ``[safety] cascade``."""
    env = os.environ.get("MAVERICK_CASCADE_SHIELD", "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    if env in ("0", "false", "no", "off"):
        return False
    try:
        from maverick.config import load_config
        return bool(load_config().get("safety", {}).get("cascade", False))
    except Exception:
        return False


def normalize_for_probe(text: str) -> str:
    """NFKC + strip invisible chars before probing. Defends against
    obfuscation that uses Unicode normalization round-tripping."""
    if not text:
        return text
    normalized = unicodedata.normalize("NFKC", text)
    return _INVISIBLE_RE.sub("", _TAG_RE.sub("", normalized))
