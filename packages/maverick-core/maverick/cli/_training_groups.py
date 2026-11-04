"""``maverick reward-model`` -- train + apply the CPU reward model.

Exposes :mod:`maverick.training.reward_model` through the main CLI (it otherwise
only had a ``python -m`` entry), so an operator can distil verifier rewards into
a fast scalar reward and rank trajectories without a GPU. Registered by import
at the end of the package __init__, like the other ``_*_groups`` modules.
"""
from __future__ import annotations

import json as _json

import click

from . import main


def _strict_json_object(raw: str) -> dict:
    """Decode one finite JSON object without silently collapsing duplicate keys."""
    from ..training.improvement_report import strict_json_object
    return strict_json_object(raw)


@main.group("reward-model")
def reward_model_group() -> None:
    """Train + apply the CPU reward model (RLAIF flywheel, no GPU).

    The model learns from verifier-reward preference pairs over structural
    trajectory features and scores new attempts -- a cheap pre-filter before a
    deep verifier pass.
    """


@reward_model_group.command("train")
@click.argument("data", type=click.Path(exists=True, dir_okay=False))
@click.option("--out", "-o", "out", required=True, type=click.Path(dir_okay=False),
              help="Output path for the learned reward-model JSON.")
@click.option("--min-margin", type=float, default=0.5, show_default=True,
              help="Minimum verifier-reward gap for a preference pair.")
@click.option("--max-pairs", type=int, default=64, show_default=True,
              help="Max preference pairs per task family.")
@click.option("--epochs", type=int, default=200, show_default=True)
@click.option("--lr", type=float, default=0.1, show_default=True)
def reward_model_train_cmd(data, out, min_margin, max_pairs, epochs, lr) -> None:
    """Train a reward model from a Klear-format trajectory JSONL (from
    ``maverick`` training.ingest)."""
    from ..training.reward_model import load_klear, train_reward_model
    rows = load_klear(data)
    if not rows:
        raise click.ClickException(f"no trajectories loaded from {data}")
    model, report = train_reward_model(
        rows, min_margin=min_margin, max_pairs_per_group=max_pairs,
        epochs=epochs, lr=lr)
    if report["pairs"] == 0:
        raise click.ClickException(
            "no preference pairs (need >=2 attempts per task family with a "
            f"reward gap >= {min_margin}); nothing to train on.")
    model.save(out)
    click.echo(
        f"trained on {report['pairs']} pairs -- {report['accuracy']:.0%} pairwise "
        f"accuracy, loss {report['loss']:.4f} -> {out}")


@reward_model_group.command("score")
@click.argument("model_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("data", type=click.Path(exists=True, dir_okay=False))
@click.option("--top", type=int, default=0,
              help="Show only the top-N highest-scoring trajectories (0 = all).")
def reward_model_score_cmd(model_path, data, top) -> None:
    """Score each trajectory in a Klear JSONL with a trained reward MODEL_PATH,
    printing ``id`` and score sorted high-to-low."""
    from ..training.reward_model import PreferenceRewardModel, load_klear
    try:
        model = PreferenceRewardModel.load(model_path)
    except (ValueError, OSError) as e:
        raise click.ClickException(f"cannot load reward model: {e}") from e
    rows = load_klear(data)
    scored = sorted(
        ({"id": r.get("id"), "score": round(model.score(r), 6)} for r in rows),
        key=lambda x: x["score"], reverse=True)
    if top > 0:
        scored = scored[:top]
    click.echo(_json.dumps(scored, indent=2))


@main.group("model-improvement")
def model_improvement_group() -> None:
    """Inspect deterministic tasksets and specialist-model candidates."""


@model_improvement_group.command("status")
def model_improvement_status_cmd() -> None:
    """Show control posture, taskset readiness, and catalog identity."""
    from ..training.improvement_report import status_report

    click.echo(_json.dumps(status_report(), indent=2, sort_keys=True))


@model_improvement_group.command("models")
@click.option("--role", required=True, type=str)
@click.option("--memory-gib", required=True, type=float)
@click.option("--context-tokens", default=16_384, show_default=True, type=int)
@click.option("--concurrency", default=1, show_default=True, type=int)
def model_improvement_models_cmd(
    role,
    memory_gib,
    context_tokens,
    concurrency,
) -> None:
    """List planning candidates for one role and memory envelope."""
    from ..training.improvement_report import candidates_report

    click.echo(_json.dumps(candidates_report(
        role, memory_gib=memory_gib, context_tokens=context_tokens,
        concurrency=concurrency,
    ), indent=2, sort_keys=True))


@model_improvement_group.command("score")
@click.argument("environment_id")
@click.argument("outputs", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--split",
    type=click.Choice(["train", "validation", "holdout"]),
    default="holdout",
    show_default=True,
)
@click.option(
    "--require-perfect",
    is_flag=True,
    help="Exit non-zero unless every selected case passes.",
)
def model_improvement_score_cmd(
    environment_id,
    outputs,
    split,
    require_perfect,
) -> None:
    """Score a CASE_ID-to-output JSON object without an LLM judge."""
    from pathlib import Path

    from ..training.improvement_report import score_report

    try:
        raw = _strict_json_object(Path(outputs).read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError, ValueError) as exc:
        raise click.ClickException(f"cannot read outputs: {exc}") from exc
    payload = score_report(environment_id, raw, split=split)
    click.echo(_json.dumps(payload, indent=2, sort_keys=True))
    if require_perfect and payload["pass_rate"] != 1.0:
        raise click.ClickException("selected split did not pass perfectly")
