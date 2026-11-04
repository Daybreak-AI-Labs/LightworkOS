"""A CPU-trainable reward model for the RLAIF flywheel.

:mod:`maverick.training.rlaif` turns verifier rewards into DPO preference pairs,
but its ``train`` loop needs a GPU + ``torch`` + a real base model — it learns
no weights without that stack. This module is the missing **offline** half: a
Bradley-Terry / logistic preference model over cheap *structural* trajectory
features that LEARNS ACTUAL WEIGHTS from the same preference pairs, in pure
Python, in milliseconds, on a CPU.

It answers "given two attempts, which did the verifier prefer?" from features
like trajectory length, error rate, and tool usage — distilling the verifier's
judgement into a fast scalar reward you can use to rank/screen new attempts
*before* paying for a deep verifier pass (mirrors the shield's trained-probe
ensemble). The learned weights are a plain JSON artifact — no pickle, no heavy
deps — so they are safe to load and ship.

The objective is the Bradley-Terry pairwise logistic loss (the same preference
likelihood DPO uses): for a pair ``(chosen, rejected)`` with confidence weight
``w``::

    p = sigmoid(score(chosen) - score(rejected))
    loss = -w * log(p)              # + L2 regularization

minimized by gradient descent on the linear feature weights. Pure, deterministic
(zero-init), and unit-tested end to end.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from .rlaif import build_preference_pairs, load_klear

# Stable feature names — the model's contract (a saved model lists exactly the
# features it was trained on). DELIBERATELY excludes ``terminal_reward`` itself:
# that IS the verifier label we are distilling, so using it as a feature would be
# circular. The model must predict the verifier's preference from CHEAP signal.
FEATURES = ("n_messages", "n_errors", "error_rate", "n_tool_calls",
            "n_think", "distinct_tools")


def featurize(row: dict) -> dict[str, float]:
    """Structural features for a Klear trajectory row (no raw text needed)."""
    messages = row.get("messages") or []
    n = len(messages)
    errors = sum(1 for m in messages if m.get("error"))
    tool_calls = sum(1 for m in messages
                     if m.get("type") == "tool_call" or m.get("name"))
    think = sum(1 for m in messages if m.get("type") == "think")
    tools = {m.get("name") for m in messages if m.get("name")}
    return {
        "n_messages": float(n),
        "n_errors": float(errors),
        "error_rate": errors / n if n else 0.0,
        "n_tool_calls": float(tool_calls),
        "n_think": float(think),
        "distinct_tools": float(len(tools)),
    }


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


def has_recorded_steps(row: dict | None) -> bool:
    """Whether structural scoring has any recorded steps to inspect."""
    return (isinstance(row, dict) and isinstance(row.get("messages"), list)
            and bool(row["messages"]) and all(isinstance(m, dict) for m in row["messages"]))


def structural_comparisons(
    pairs: list[dict], rows_by_id: dict[str, dict],
) -> tuple[list[dict], dict[str, int]]:
    """Select comparisons supported by recorded steps on BOTH attempts.

    Empty steps mean unavailable evidence, not an attempt with no errors or
    effort. Native rejected drafts and scored answer candidates intentionally
    have no steps: keep their DPO answer pairs intact, but do not train this
    structural model from them. Identical features cannot establish an order.
    """
    counts = dict.fromkeys(("candidates", "eligible", "skipped", "unresolved",
                            "missing_steps", "indistinguishable", "no_confidence"), 0)
    counts["candidates"] = len(pairs)
    eligible = []
    for pair in pairs:
        chosen = rows_by_id.get(pair.get("chosen_id"))
        rejected = rows_by_id.get(pair.get("rejected_id"))
        if not has_recorded_steps(chosen) or not has_recorded_steps(rejected):
            counts["missing_steps"] += 1
            counts["skipped"] += 1
            continue
        weight = pair.get("weight", 1.0)
        if type(weight) not in {float, int} or not math.isfinite(weight) or weight <= 0:
            counts["no_confidence"] += 1
            counts["skipped"] += 1
            continue
        if featurize(chosen) == featurize(rejected):
            counts["indistinguishable"] += 1
            counts["unresolved"] += 1
            continue
        eligible.append(pair)
    counts["eligible"] = len(eligible)
    return eligible, counts


def training_comparisons(
    rows: list[dict], *, min_margin: float = 0.5, max_pairs_per_group: int = 64,
) -> tuple[list[dict], dict[str, int]]:
    """Use the unchanged bounded DPO selector, then assess structural evidence."""
    pairs = build_preference_pairs(rows, min_margin=min_margin,
                                   max_pairs_per_group=max_pairs_per_group)
    return structural_comparisons(pairs, {row.get("id"): row for row in rows})


class PreferenceRewardModel:
    """A linear reward model: ``score(row) = Σ weights[f] * feature[f]``.

    Trained from verifier-reward preference pairs via the Bradley-Terry logistic
    loss. No intercept: a constant cancels in every pairwise difference, so the
    score is only meaningful for *ranking* (which is all a reward model needs)."""

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self.weights: dict[str, float] = dict.fromkeys(FEATURES, 0.0)
        if weights:
            self.weights.update({k: float(v) for k, v in weights.items()})

    def score(self, row: dict) -> float:
        feats = featurize(row)
        return sum(self.weights.get(f, 0.0) * feats.get(f, 0.0) for f in self.weights)

    def _score_feats(self, feats: dict[str, float]) -> float:
        return sum(self.weights.get(f, 0.0) * feats.get(f, 0.0) for f in self.weights)

    def fit(
        self,
        pairs: list[dict],
        rows_by_id: dict[str, dict],
        *,
        lr: float = 0.1,
        epochs: int = 200,
        l2: float = 1e-4,
    ) -> dict:
        """Learn weights from preference pairs. Returns a training report
        ``{"pairs", "epochs", "loss", "accuracy"}`` (accuracy = fraction of
        pairs the final model orders correctly). Idempotent given the same data
        (zero-init, deterministic)."""
        # Precompute each pair's feature DIFFERENCE (chosen - rejected) + weight;
        # missing/unknown ids are skipped so a partial corpus still trains.
        diffs: list[tuple[dict[str, float], float]] = []
        eligible, counts = structural_comparisons(pairs, rows_by_id)
        for p in eligible:
            c = rows_by_id.get(p.get("chosen_id"))
            r = rows_by_id.get(p.get("rejected_id"))
            if c is None or r is None:
                continue
            fc, fr = featurize(c), featurize(r)
            d = {f: fc.get(f, 0.0) - fr.get(f, 0.0) for f in FEATURES}
            diffs.append((d, float(p.get("weight", 1.0))))

        report = {"pairs": len(diffs), "epochs": 0, "loss": 0.0, "accuracy": 0.0,
                  **counts}
        if not diffs:
            return report

        for _ in range(max(1, epochs)):
            grad = dict.fromkeys(FEATURES, 0.0)
            for d, w in diffs:
                p_correct = _sigmoid(self._score_feats(d))
                # dL/dw_f = -weight * (1 - p) * d_f  ; + L2
                coeff = -w * (1.0 - p_correct)
                for f in FEATURES:
                    grad[f] += coeff * d[f]
            for f in FEATURES:
                grad[f] = grad[f] / len(diffs) + l2 * self.weights[f]
                self.weights[f] -= lr * grad[f]

        report["epochs"] = max(1, epochs)
        report["loss"] = self._mean_loss(diffs)
        report["accuracy"] = self._accuracy(diffs)
        return report

    def _mean_loss(self, diffs: list[tuple[dict[str, float], float]]) -> float:
        total = 0.0
        for d, w in diffs:
            p = _sigmoid(self._score_feats(d))
            total += -w * math.log(max(p, 1e-12))
        return total / len(diffs)

    def _accuracy(self, diffs: list[tuple[dict[str, float], float]]) -> float:
        correct = sum(1 for d, _w in diffs if self._score_feats(d) > 0)
        return correct / len(diffs)

    # -- persistence (plain JSON, safe to load) -----------------------------
    def to_dict(self) -> dict:
        return {"type": "bradley_terry_linear", "features": list(FEATURES),
                "weights": dict(self.weights)}

    def save(self, path: str | Path) -> None:
        Path(path).expanduser().write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> PreferenceRewardModel:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("reward model must be a JSON object")
        weights = data.get("weights") or {}
        if not isinstance(weights, dict):
            raise ValueError("reward model 'weights' must be an object")
        return cls(weights={str(k): float(v) for k, v in weights.items()})


def train_reward_model(
    rows: list[dict], *, min_margin: float = 0.5, max_pairs_per_group: int = 64,
    lr: float = 0.1, epochs: int = 200, l2: float = 1e-4,
) -> tuple[PreferenceRewardModel, dict]:
    """End-to-end: Klear rows -> preference pairs -> fitted reward model.
    Returns ``(model, report)``."""
    pairs = build_preference_pairs(
        rows, min_margin=min_margin, max_pairs_per_group=max_pairs_per_group)
    rows_by_id = {r.get("id"): r for r in rows}
    model = PreferenceRewardModel()
    report = model.fit(pairs, rows_by_id, lr=lr, epochs=epochs, l2=l2)
    return model, report


def reweight_pairs_with_model(
    pairs: list[dict], rows_by_id: dict[str, dict], model: PreferenceRewardModel,
    *, disagree_penalty: float = 0.5,
) -> dict:
    """Cross-check verifier preference labels with a learned reward model.

    The verifier produced each ``(chosen, rejected)`` pair; a cheap learned
    structural model supplies an additional ranking signal. It is trained on
    verifier labels, so it is not independent evidence of answer quality.
    Where the model AGREES
    (``score(chosen) > score(rejected)``) the pair's ``weight`` is kept; where it
    DISAGREES the weight is scaled by ``disagree_penalty``. Missing steps,
    indistinguishable features and tied model scores abstain: the original DPO
    weight stays unchanged. Mutates ``pairs`` in place and returns a report
    ``{"pairs", "agree", "agreement_rate"}``. Pairs whose ids aren't resolvable
    are left unchanged and excluded from the rate."""
    agree = disagree = tied = 0
    eligible, counts = structural_comparisons(pairs, rows_by_id)
    for p in eligible:
        c = rows_by_id.get(p.get("chosen_id"))
        r = rows_by_id.get(p.get("rejected_id"))
        if c is None or r is None:
            continue
        chosen_score, rejected_score = model.score(c), model.score(r)
        if (not math.isfinite(chosen_score) or not math.isfinite(rejected_score)
                or math.isclose(chosen_score, rejected_score, rel_tol=1e-12, abs_tol=1e-12)):
            tied += 1
        elif chosen_score > rejected_score:
            agree += 1
        else:
            disagree += 1
            p["weight"] = float(p.get("weight", 1.0)) * float(disagree_penalty)
    scored = agree + disagree
    return {"pairs": len(pairs), "agree": agree,
            "agreement_rate": (agree / scored) if scored else 0.0,
            **counts, "scored": scored, "disagree": disagree, "tied": tied,
            "abstained": len(pairs) - scored}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python -m maverick.training.reward_model",
        description="Train a CPU reward model from verifier-reward preference pairs.")
    ap.add_argument("--data", required=True, type=Path,
                    help="Klear-format JSONL of trajectories (from training.ingest).")
    ap.add_argument("--out", required=True, type=Path,
                    help="Output path for the learned reward-model JSON.")
    ap.add_argument("--min-margin", type=float, default=0.5)
    ap.add_argument("--max-pairs", type=int, default=64)
    ap.add_argument("--lr", type=float, default=0.1)
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--l2", type=float, default=1e-4)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    rows = load_klear(args.data)
    model, report = train_reward_model(
        rows, min_margin=args.min_margin, max_pairs_per_group=args.max_pairs,
        lr=args.lr, epochs=args.epochs, l2=args.l2)
    model.save(args.out)
    print(f"trained reward model on {report['pairs']} pairs "
          f"({report['accuracy']:.0%} pairwise accuracy, loss {report['loss']:.4f}) "
          f"-> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
