"""Compaction v6 hybrid — a learned-from-ledger STRATEGY picker.

The rule ladder (``maverick.tools.compaction_classifier``) picks among the
real strategy registry — ``truncate | structural | retrieval | summarize`` —
with fixed thresholds. This module learns which strategy actually works for
each conversation *shape*, from this instance's own outcomes:

  - deterministic feature extraction from the message window (counts only:
    messages, tool-result chars ratio, code-fence density, distinct tools,
    age span — no content leaves the process);
  - a per-(feature-bucket, strategy) outcome ledger with epsilon-greedy
    selection over an injected PRNG — reusing
    :class:`maverick.cost.bandit.ContextualBandit` (the existing atomic
    0600 JSON ledger + bandit helper) rather than duplicating it;
  - cold start (no outcomes for a bucket) falls back to the existing rule
    ladder, and **every** failure path falls open to the ladder/structural
    default — compaction must never crash a run;
  - an optional offline trainer :func:`fit` — pure-python logistic
    regression over the ledger (a few hundred gradient steps; **no torch, no
    ``[training]`` extra needed**) — whose weights persist as a versioned
    JSON the picker consults when present.

Honesty note: this is an **online-learning heuristic, not a pretrained
model**. Lightwork ships NO trained weights; the picker starts as the rule
ladder and only ever reflects outcomes recorded on this instance (or weights
the operator trained themselves with :func:`fit`).

Off by default: ``[compaction] hybrid = true`` (or
``MAVERICK_COMPACTION_HYBRID=1``) enables :func:`pick_strategy`; disabled, it
returns the ladder's pick — existing behavior.

Status: EXPERIMENTAL, **wired into the live agent compaction path** — with the
knob on, ``agent.py`` -> ``compaction.plugins.compact_with`` consults a shared
persistent :class:`HybridPicker`, maps this module's abstract shrink vocabulary
(``truncate | structural | retrieval | summarize``) onto the registered
implementation that realizes it (``plugins._ABSTRACT_TO_LIVE``: truncate /
structural -> ``heuristic``, retrieval -> ``graph``, summarize -> ``learned``),
runs it, and records the achieved shrink back into the ledger — every step
fail-open to the built-in default. An explicitly configured strategy
(``MAVERICK_COMPACTION_STRATEGY`` / ``[context] compaction_strategy``) always
wins over the picker.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from random import Random

from ..cost.bandit import ContextualBandit

log = logging.getLogger(__name__)

# The real strategy registry (tools/compaction_classifier.py's ladder outputs).
STRATEGIES = ("truncate", "structural", "retrieval", "summarize")
# The kernel's actual default behavior (compaction.compact_messages emits
# structural references) — the terminal fail-open answer.
FALLBACK_STRATEGY = "structural"

WEIGHTS_SCHEMA = "maverick-compaction-hybrid-weights/1"
FEATURE_NAMES = ("messages", "tool_ratio", "code_density", "distinct_tools", "age_span")
DEFAULT_EPSILON = 0.1


def enabled() -> bool:
    if os.environ.get("MAVERICK_COMPACTION_HYBRID", "").strip().lower() in {
            "1", "true", "yes", "on"}:
        return True
    try:
        from ..config import load_config
        return bool(((load_config() or {}).get("compaction") or {}).get("hybrid", False))
    except Exception:  # pragma: no cover - config never blocks compaction
        return False


# ---------------------------------------------------------------------------
# Deterministic features + buckets
# ---------------------------------------------------------------------------

def _text_of(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for blk in content:
            if isinstance(blk, dict):
                if blk.get("type") == "text":
                    parts.append(str(blk.get("text", "") or ""))
                elif blk.get("type") == "tool_result":
                    parts.append(_text_of(blk.get("content", "")))
            else:
                parts.append(str(blk))
        return "\n".join(parts)
    return str(content or "")


def extract_features(messages: list[dict]) -> dict:
    """Deterministic shape counts for a message window. Pure, content-free."""
    msgs = [m for m in messages if isinstance(m, dict)]
    total_chars = 0
    tool_chars = 0
    fences = 0
    tools: set[str] = set()
    stamps: list[float] = []
    for m in msgs:
        content = m.get("content")
        text = _text_of(content)
        total_chars += len(text)
        fences += text.count("```")
        if isinstance(content, list):
            for blk in content:
                if not isinstance(blk, dict):
                    continue
                if blk.get("type") == "tool_result":
                    tool_chars += len(_text_of(blk.get("content", "")))
                elif blk.get("type") == "tool_use":
                    tools.add(str(blk.get("name", "") or "?"))
        ts = m.get("ts")
        if isinstance(ts, (int, float)) and not isinstance(ts, bool):
            stamps.append(float(ts))
    n = len(msgs)
    return {
        "messages": n,
        "total_chars": total_chars,
        "tool_ratio": round(tool_chars / total_chars, 4) if total_chars else 0.0,
        "code_density": round(fences / n, 4) if n else 0.0,
        "distinct_tools": len(tools),
        "age_span": round(max(stamps) - min(stamps), 3) if len(stamps) >= 2 else 0.0,
    }


# Bucket edges, documented so a ledger key decodes back to a feature point.
_BUCKETS = {
    "messages": (8, 24, 64),          # m0 <8, m1 <24, m2 <64, m3 >=64
    "tool_ratio": (0.25, 0.5, 0.75),  # r0..r3
    "code_density": (0.001, 0.5),     # c0 none, c1 some, c2 heavy
    "distinct_tools": (1, 4),         # t0 none, t1 1-3, t2 4+
    "age_span": (1.0, 600.0),         # a0 none, a1 <10min, a2 long
}
# Representative midpoints per bucket index, used to decode a ledger key back
# into a (normalized) feature vector for the offline trainer.
_BUCKET_POINTS = {
    "messages": (4, 16, 44, 96),
    "tool_ratio": (0.12, 0.37, 0.62, 0.87),
    "code_density": (0.0, 0.25, 1.0),
    "distinct_tools": (0, 2, 6),
    "age_span": (0.0, 300.0, 1800.0),
}
_NORMALIZERS = {
    "messages": 96.0,
    "tool_ratio": 1.0,
    "code_density": 4.0,
    "distinct_tools": 8.0,
    "age_span": 3600.0,
}
_KEY_RE = re.compile(r"^m(\d)\|r(\d)\|c(\d)\|t(\d)\|a(\d)$")


def _bucket_index(name: str, value: float) -> int:
    idx = 0
    for edge in _BUCKETS[name]:
        if value >= edge:
            idx += 1
    return idx


def bucket_key(features: dict) -> str:
    parts = []
    for prefix, name in zip("mrcta", FEATURE_NAMES, strict=False):
        parts.append(f"{prefix}{_bucket_index(name, float(features.get(name, 0)))}")
    return "|".join(parts)


def _normalize(name: str, value: float) -> float:
    return max(0.0, min(1.0, float(value) / _NORMALIZERS[name]))


def feature_vector(features: dict) -> list[float]:
    """Normalized [0,1] vector in FEATURE_NAMES order (bias appended by fit)."""
    return [_normalize(n, float(features.get(n, 0))) for n in FEATURE_NAMES]


def _vector_from_bucket(key: str) -> list[float] | None:
    m = _KEY_RE.fullmatch(key)
    if not m:
        return None
    vec = []
    for name, raw in zip(FEATURE_NAMES, m.groups(), strict=False):
        points = _BUCKET_POINTS[name]
        idx = min(int(raw), len(points) - 1)
        vec.append(_normalize(name, points[idx]))
    return vec


# ---------------------------------------------------------------------------
# Cold-start default: the existing rule ladder
# ---------------------------------------------------------------------------

def default_strategy(features: dict) -> str:
    """The existing deterministic ladder's pick (fail-open to structural)."""
    try:
        from ..tools.compaction_classifier import _pick
        out = _pick({
            "turns": int(features.get("messages", 0)),
            "tokens": int(features.get("total_chars", 0)) // 4,
            "has_code": float(features.get("code_density", 0)) > 0,
            "has_tool_output": float(features.get("tool_ratio", 0)) > 0,
            "pinned_ratio": 0.0,
        })
        # "_pick" returns "STRATEGY <name>: <reason>".
        name = out.split()[1].rstrip(":") if out.startswith("STRATEGY") else ""
        if name in STRATEGIES:
            return name
    except Exception as e:  # pragma: no cover - ladder is pure; belt-and-braces
        log.debug("compaction hybrid: ladder default failed: %s", e)
    return FALLBACK_STRATEGY


# ---------------------------------------------------------------------------
# Weights (optional, offline-trained)
# ---------------------------------------------------------------------------

def _sigmoid(z: float) -> float:
    if z < -35:
        return 0.0
    if z > 35:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def fit(ledger: ContextualBandit | dict | Path | str, *,
        iterations: int = 300, lr: float = 0.5,
        now: float | None = None) -> dict:
    """Offline trainer: pure-python logistic regression over the outcome ledger.

    One model per strategy: predicts P(success) from the bucket's feature
    point, weighting each (bucket, strategy) cell by its pull count. Returns a
    versioned weights dict (``WEIGHTS_SCHEMA``) for :func:`save_weights`.
    No torch / no ``[training]`` extra — this is a few hundred gradient steps
    over at most a few hundred aggregated cells.
    """
    if isinstance(ledger, (str, Path)):
        ledger = ContextualBandit(path=Path(ledger))
    if isinstance(ledger, ContextualBandit):
        table = {ctx: {a: {"pulls": v.pulls, "mean": v.mean}
                       for a, v in arms.items()}
                 for ctx, arms in ledger._table.items()}
    else:
        table = {ctx: {a: {"pulls": int(d.get("pulls", 0)),
                           "mean": (float(d.get("total_reward", 0.0)) /
                                    max(1, int(d.get("pulls", 0))))}
                       for a, d in arms.items()}
                 for ctx, arms in ledger.items()}

    dim = len(FEATURE_NAMES) + 1  # + bias
    strategies_out: dict[str, list[float]] = {}
    for strategy in STRATEGIES:
        rows: list[tuple[list[float], float, float]] = []  # (x, y, weight)
        for ctx, arms in table.items():
            cell = arms.get(strategy)
            if not cell or cell["pulls"] <= 0:
                continue
            vec = _vector_from_bucket(ctx)
            if vec is None:
                continue
            y = max(0.0, min(1.0, float(cell["mean"])))
            rows.append((vec + [1.0], y, float(cell["pulls"])))
        if not rows:
            continue
        total_w = sum(w for _, _, w in rows)
        weights = [0.0] * dim
        for _ in range(max(1, int(iterations))):
            grad = [0.0] * dim
            for x, y, w in rows:
                err = _sigmoid(sum(wi * xi for wi, xi in zip(weights, x, strict=False))) - y
                for j in range(dim):
                    grad[j] += w * err * x[j]
            for j in range(dim):
                weights[j] -= lr * grad[j] / total_w
        strategies_out[strategy] = [round(w, 6) for w in weights]

    ts = time.time() if now is None else now
    return {
        "schema": WEIGHTS_SCHEMA,
        "trained_at": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
        "features": list(FEATURE_NAMES) + ["bias"],
        "strategies": strategies_out,
    }


def save_weights(weights: dict, path: Path | str) -> None:
    p = Path(path)
    from ..file_lock import atomic_write_text

    atomic_write_text(p, json.dumps(weights, sort_keys=True))


def load_weights(path: Path | str | None) -> dict | None:
    """Load a weights file; None unless it is a well-formed WEIGHTS_SCHEMA doc."""
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema") != WEIGHTS_SCHEMA:
        return None
    strategies = data.get("strategies")
    if not isinstance(strategies, dict):
        return None
    dim = len(FEATURE_NAMES) + 1
    clean = {s: [float(w) for w in ws] for s, ws in strategies.items()
             if s in STRATEGIES and isinstance(ws, list) and len(ws) == dim}
    if not clean:
        return None
    return {**data, "strategies": clean}


# ---------------------------------------------------------------------------
# The picker
# ---------------------------------------------------------------------------

def default_ledger_path() -> Path:
    from ..paths import data_dir
    return data_dir() / "compaction_hybrid.json"


def default_weights_path() -> Path:
    from ..paths import data_dir
    return data_dir() / "compaction_hybrid_weights.json"


@dataclass
class HybridPicker:
    """Epsilon-greedy strategy picker over the outcome ledger (+ optional weights).

    Decision order, all fail-open:
      1. trained weights present -> argmax of per-strategy P(success)
         (epsilon exploration still applies; strategies absent from the
         weights score a neutral 0.5 prior);
      2. ledger has outcomes for this bucket -> bandit choice;
      3. cold bucket -> the existing rule ladder's pick;
      x. any error anywhere -> ladder/structural default, never a raise.
    """

    epsilon: float = DEFAULT_EPSILON
    rng: Random = field(default_factory=lambda: Random(0))
    ledger_path: Path | None = None
    weights_path: Path | None = None
    _bandit: ContextualBandit = field(init=False, repr=False)

    def __post_init__(self):
        self._bandit = ContextualBandit(
            epsilon=self.epsilon, rng=self.rng, path=self.ledger_path)

    def pick(self, messages: list[dict]) -> tuple[str, str]:
        """Return ``(strategy, reason)`` for a message window. Never raises."""
        try:
            feats = extract_features(messages)
            bucket = bucket_key(feats)
            weights = load_weights(self.weights_path)
            if weights:
                if self.rng.random() < self.epsilon:
                    choice = self.rng.choice(list(STRATEGIES))
                    return choice, f"explore (weights, bucket {bucket})"
                x = feature_vector(feats) + [1.0]
                scores = {}
                for s in STRATEGIES:
                    ws = weights["strategies"].get(s)
                    scores[s] = (_sigmoid(sum(w * xi for w, xi in zip(ws, x, strict=False)))
                                 if ws else 0.5)
                best = max(STRATEGIES, key=lambda s: (scores[s], s))
                return best, (f"weights p={scores[best]:.2f} (bucket {bucket})")
            stats = self._bandit.stats(bucket)
            if not any(v["pulls"] for v in stats.values()):
                return default_strategy(feats), f"cold-start ladder (bucket {bucket})"
            chosen = self._bandit.choose(bucket, list(STRATEGIES))
            return chosen or default_strategy(feats), f"ledger (bucket {bucket})"
        except Exception as e:
            log.warning("compaction hybrid: pick failed open: %s", e)
            return FALLBACK_STRATEGY, f"fail-open: {e}"

    def record(self, messages: list[dict], strategy: str, success: bool) -> None:
        """Record one outcome into the ledger. Fail-open no-op on any error."""
        try:
            if strategy not in STRATEGIES:
                return
            bucket = bucket_key(extract_features(messages))
            self._bandit.record(bucket, strategy, 1.0 if success else 0.0)
        except Exception as e:
            log.debug("compaction hybrid: record failed open: %s", e)


def pick_strategy(messages: list[dict], picker: HybridPicker | None = None
                  ) -> tuple[str, str]:
    """Module entry point honoring the ``[compaction] hybrid`` knob.

    Disabled (the default): the existing rule ladder decides — behavior
    unchanged. Enabled: a shared persistent picker decides.
    """
    try:
        if not enabled():
            feats = extract_features(messages)
            return default_strategy(feats), "hybrid disabled: rule ladder"
        if picker is None:
            from ..file_lock import ensure_private_directory

            ensure_private_directory(default_ledger_path().parent)
            picker = HybridPicker(ledger_path=default_ledger_path(),
                                  weights_path=default_weights_path())
        return picker.pick(messages)
    except Exception as e:
        log.warning("compaction hybrid: pick_strategy failed open: %s", e)
        return FALLBACK_STRATEGY, f"fail-open: {e}"


__all__ = [
    "STRATEGIES",
    "FALLBACK_STRATEGY",
    "WEIGHTS_SCHEMA",
    "FEATURE_NAMES",
    "enabled",
    "extract_features",
    "bucket_key",
    "feature_vector",
    "default_strategy",
    "fit",
    "save_weights",
    "load_weights",
    "HybridPicker",
    "pick_strategy",
    "default_ledger_path",
    "default_weights_path",
]
