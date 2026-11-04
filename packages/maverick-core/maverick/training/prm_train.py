"""Train an AgentPRM head from labeled trajectories (arxiv:2511.08325).

Operator-run script — needs GPU/torch + trajectory volume, which is
operator-side work, not in-kernel. torch is an OPTIONAL extra; it is
imported LAZILY inside main()/train() and never at module top level so
the kernel and its tests run without it.

Usage:

    python -m maverick.training.prm_train --data trajectories.jsonl \\
        --out ./prm_head [--epochs N --lr 1e-2]

Input: Klear-format JSONL (see training/schema.py::to_klear_jsonl).
Output: a model directory ./prm_head containing head.pt + head.json,
loadable by maverick.prm.LearnedPRM.

The pure helpers (load_klear, rows_to_examples) are torch-free and unit
tested; only train()/save_head()/main() touch torch.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..prm import FEATURE_NAMES, ROLE_VOCAB, StepContext, step_features


def load_klear(path: str | Path) -> list[dict]:
    """Read a Klear-format JSONL file into a list of row dicts."""
    rows: list[dict] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def rows_to_examples(rows: list[dict]) -> list[tuple[list[float], list[float]]]:
    """Reconstruct per-step (features, [promise, progress]) training pairs.

    Each Klear row carries parallel `messages` + `rewards` arrays (see
    schema.to_klear_jsonl). For every step we rebuild a StepContext using
    the same field meanings as training/ingest.py:
      * type == "final"     -> is_final
      * type == "tool_call" -> tool_succeeded = False if error else True
      * role comes from the message
    Steps whose promise/progress labels are None are skipped.
    """
    examples: list[tuple[list[float], list[float]]] = []
    for row in rows:
        messages = row.get("messages", []) or []
        rewards = row.get("rewards", []) or []
        prior = 0.5
        for i, msg in enumerate(messages):
            reward = rewards[i] if i < len(rewards) else {}
            promise = reward.get("promise")
            progress = reward.get("progress")

            action_type = msg.get("type", "")
            error = msg.get("error")
            name = msg.get("name") or None
            is_final = action_type == "final"
            if action_type == "tool_call":
                tool_succeeded = error is None
            else:
                tool_succeeded = None

            ctx = StepContext(
                goal_id=0,
                step_index=reward.get("step", i),
                role=msg.get("role", ""),
                tool_name=name,
                tool_succeeded=tool_succeeded,
                is_final=is_final,
                error=error,
                prior_step_score=prior,
            )
            x = step_features(ctx)
            if promise is None or progress is None:
                continue
            prior = float(promise)
            examples.append((x, [float(promise), float(progress)]))
    return examples


def train(
    examples: list[tuple[list[float], list[float]]],
    *,
    epochs: int,
    lr: float,
    hidden_dim: int = 16,
):
    """Fit the MLP head with Adam + MSE. Returns a torch state_dict.

    Lazily imports torch; the caller is responsible for ensuring it is
    installed (main() prints an actionable message otherwise).
    """
    import torch

    if not examples:
        raise ValueError("no training examples")

    xs = torch.tensor([x for x, _ in examples], dtype=torch.float32)
    ys = torch.tensor([y for _, y in examples], dtype=torch.float32)

    input_dim = len(FEATURE_NAMES)
    net = torch.nn.Sequential(
        torch.nn.Linear(input_dim, hidden_dim),
        torch.nn.ReLU(),
        torch.nn.Linear(hidden_dim, 2),
    )
    opt = torch.optim.Adam(net.parameters(), lr=lr)
    loss_fn = torch.nn.MSELoss()
    for _ in range(epochs):
        opt.zero_grad()
        pred = torch.tanh(net(xs))
        loss = loss_fn(pred, ys)
        loss.backward()
        opt.step()
    return net.state_dict()


def save_head(out_dir: str | Path, state_dict, *, hidden_dim: int = 16) -> None:
    """Write head.pt + head.json to out_dir per the shared artifact spec."""
    import torch

    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    torch.save(state_dict, d / "head.pt")
    meta = {
        "version": 1,
        "input_dim": len(FEATURE_NAMES),
        "hidden_dim": hidden_dim,
        "feature_names": FEATURE_NAMES,
        "role_vocab": ROLE_VOCAB,
    }
    (d / "head.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", required=True, help="Klear-format JSONL input")
    ap.add_argument("--out", required=True, help="Output model directory")
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--lr", type=float, default=1e-2)
    ap.add_argument("--hidden-dim", type=int, default=16)
    args = ap.parse_args()

    try:
        import torch  # noqa: F401
    except ImportError:
        print(
            "torch is required to train the PRM head. Install it with:\n"
            "    python -m pip install -e './packages/maverick-core[training]'",
            file=sys.stderr,
        )
        return 1

    rows = load_klear(args.data)
    examples = rows_to_examples(rows)
    if not examples:
        print("no labeled steps found in input; nothing to train", file=sys.stderr)
        return 1

    state = train(
        examples, epochs=args.epochs, lr=args.lr, hidden_dim=args.hidden_dim
    )
    save_head(args.out, state, hidden_dim=args.hidden_dim)
    print(
        f"trained PRM head on {len(examples)} steps -> {args.out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
