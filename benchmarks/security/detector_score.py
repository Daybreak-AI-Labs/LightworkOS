"""Scored detector benchmark for Lightwork's shield (offline, no LLM).

Runs the labelled corpus (``corpus.py``) through every shield backend that
works without the agent-shield SDK or an API key, and reports TPR / FPR / F1
with Wilson 95% confidence intervals, a per-obfuscation evasion sweep, and a
leakage guard.

Honesty rules baked in:
  * TPR is reported separately for the ``train`` split (rules tuned on it ->
    a regression check, not skill) and the ``heldout`` split (novel -> the
    real capability signal). F1 uses heldout positives only.
  * Backends that need the full SDK or an LLM are listed as UNAVAILABLE
    rather than silently omitted.
  * This number is an internal dashboard. It must NOT be quoted as the
    public docs/safety.md figure -- see README.

Run:  python benchmarks/security/detector_score.py            # print + write
      python benchmarks/security/detector_score.py --no-write # print only
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import sys
from collections.abc import Callable
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for _p in (_ROOT, _ROOT / "packages" / "maverick-shield", _ROOT / "packages" / "maverick-core"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maverick_shield import builtin_rules, cascade  # noqa: E402

from benchmarks.security import corpus  # noqa: E402

try:
    from maverick.safety.jailbreak_heuristics import score_text  # noqa: E402
    _HEUR = True
except Exception:  # pragma: no cover - core must be importable in CI
    _HEUR = False

_HEUR_THRESHOLD = 0.6


def _heuristics(t: str) -> bool:
    return _HEUR and score_text(t)[0] >= _HEUR_THRESHOLD


# Offline backends: name -> predict(text) -> blocked?
BACKENDS: dict[str, Callable[[str], bool]] = {
    "builtin@high": lambda t: builtin_rules.scan(t, block_threshold="high")[0],
    "builtin@medium": lambda t: builtin_rules.scan(t, block_threshold="medium")[0],
    "heuristics@0.6": _heuristics,
    "cascade_probe": lambda t: cascade.cheap_probe(t).flagged,
    # The realistic posture when the SDK is absent: regex OR weighted scorer.
    "defense_in_depth": lambda t: builtin_rules.scan(t, "high")[0] or _heuristics(t),
}

# Backends we cannot measure here, reported for honesty (not silently dropped).
UNAVAILABLE = {
    "agent_shield_sdk": (
        "unpublished full SDK; unavailable from public PyPI"
    ),
    "cascade_deep_llm": "needs an LLM judge + API key (MAVERICK_CASCADE_SHIELD=1)",
}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% CI for a proportion; (0,0) for an empty sample."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(cases, predict, want_blocked: bool) -> tuple[int, int]:
    """(#predictions matching want_blocked, total) over the given cases."""
    n = len(cases)
    k = sum(1 for c in cases if predict(c.text) == want_blocked)
    return k, n


def evaluate(predict) -> dict:
    cases = corpus.load_all()
    train = [c for c in cases if c.split == "train"]
    held = [c for c in cases if c.split == "heldout"]
    benign = [c for c in cases if c.split == "benign"]

    tp_train, n_train = _rate(train, predict, True)
    tp_held, n_held = _rate(held, predict, True)
    tn, n_benign = _rate(benign, predict, False)          # benign correctly NOT blocked
    fp = n_benign - tn                                     # the rest are false positives

    precision_h = tp_held / (tp_held + fp) if (tp_held + fp) else 0.0
    recall_h = tp_held / n_held if n_held else 0.0
    f1_h = (2 * precision_h * recall_h / (precision_h + recall_h)
            if (precision_h + recall_h) else 0.0)

    misses = [(c.category, c.text) for c in held if not predict(c.text)]
    false_pos = [(c.category, c.text) for c in benign if predict(c.text)]
    return {
        "tpr_train": (tp_train, n_train, wilson(tp_train, n_train)),
        "tpr_heldout": (tp_held, n_held, wilson(tp_held, n_held)),
        "fpr_benign": (fp, n_benign, wilson(fp, n_benign)),
        "precision_heldout": precision_h,
        "f1_heldout": f1_h,
        "heldout_misses": misses,
        "false_positives": false_pos,
    }


def evasion(predict) -> dict[str, tuple[int, int]]:
    """Per-obfuscation TPR over the held-out attacks (deobfuscation stress)."""
    held = [c for c in corpus.load_all() if c.split == "heldout"]
    out: dict[str, tuple[int, int]] = {}
    for name, fn in corpus.obfuscations().items():
        k = sum(1 for c in held if predict(fn(c.text)))
        out[name] = (k, len(held))
    return out


def train_overlap(texts: list[str]) -> list[str]:
    """Leakage guard: which of `texts` already appear in the train corpus.

    A future external/held-out benchmark MUST run its prompts through this so
    a phrase the rules were tuned on can't sneak in and inflate the score.
    """
    def norm(s: str) -> str:
        return " ".join(s.lower().split())

    train = {norm(c.text) for c in corpus.load_all() if c.split == "train"}
    return [t for t in texts if norm(t) in train]


def _pct(k: int, n: int) -> str:
    return f"{(100.0 * k / n):.1f}%" if n else "n/a"


def summary() -> dict:
    """Machine-readable results for all backends (used by the smoke test)."""
    return {name: evaluate(fn) for name, fn in BACKENDS.items()}


def _render(results: dict, eva: dict) -> str:
    today = _dt.date.today().isoformat()
    lines = [
        "# Shield detector benchmark — RESULTS",
        "",
        f"_Generated by `benchmarks/security/detector_score.py` on {today}. "
        "source=measured, offline (no SDK, no LLM)._",
        "",
        "> **Not the public number.** `train` TPR is a regression check on the "
        "corpus the rules were tuned on — not detection skill. The honest "
        "capability signal is `heldout` TPR / F1. See README and RUNBOOK for the "
        "credible held-out + end-to-end methodology (v2).",
        "",
        "| backend | TPR train | TPR heldout (95% CI) | FPR benign (95% CI) | F1 heldout |",
        "|---|---|---|---|---|",
    ]
    for name, r in results.items():
        kt, nt, _ = r["tpr_train"]
        kh, nh, (hlo, hhi) = r["tpr_heldout"]
        kf, nf, (flo, fhi) = r["fpr_benign"]
        lines.append(
            f"| `{name}` | {_pct(kt, nt)} | {_pct(kh, nh)} "
            f"[{hlo*100:.0f}–{hhi*100:.0f}] | {_pct(kf, nf)} "
            f"[{flo*100:.0f}–{fhi*100:.0f}] | {r['f1_heldout']:.3f} |"
        )
    lines += ["", "## Backends not measured here", ""]
    for name, why in UNAVAILABLE.items():
        lines.append(f"- `{name}` — {why}")
    lines += ["", "## Evasion sweep (TPR on held-out attacks, `defense_in_depth`)", ""]
    for tname, (k, n) in eva.items():
        lines.append(f"- `{tname}`: {_pct(k, n)}")
    # Surface the gaps so they can't hide behind an average.
    misses = results["defense_in_depth"]["heldout_misses"]
    fps = results["defense_in_depth"]["false_positives"]
    lines += ["", "## Held-out misses (`defense_in_depth`)", ""]
    lines += [f"- ({cat}) {txt}" for cat, txt in misses] or ["- none"]
    lines += ["", "## False positives (`defense_in_depth`)", ""]
    lines += [f"- ({cat}) {txt}" for cat, txt in fps] or ["- none"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-write", action="store_true", help="print only; don't write artifacts")
    args = ap.parse_args(argv)

    results = summary()
    eva = evasion(BACKENDS["defense_in_depth"])
    report = _render(results, eva)
    print(report)

    if not args.no_write:
        out_dir = Path(__file__).resolve().parent
        (out_dir / "RESULTS.md").write_text(report, encoding="utf-8")
        with (out_dir / "results.jsonl").open("w", encoding="utf-8") as f:
            for name, r in results.items():
                row = {
                    "backend": name,
                    "tpr_train": r["tpr_train"][0] / max(1, r["tpr_train"][1]),
                    "tpr_heldout": r["tpr_heldout"][0] / max(1, r["tpr_heldout"][1]),
                    "fpr_benign": r["fpr_benign"][0] / max(1, r["fpr_benign"][1]),
                    "f1_heldout": r["f1_heldout"],
                    "source": "measured",
                }
                f.write(json.dumps(row) + "\n")
        print(f"wrote {out_dir/'RESULTS.md'} and {out_dir/'results.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
