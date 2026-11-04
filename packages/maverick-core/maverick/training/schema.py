"""Trajectory schema compatible with Klear-AgentForge (arxiv:2511.05951).

Klear publishes a fully open SFT + RL pipeline for long-horizon
agents; matching their schema means Lightwork trajectories can be
fed directly into their training scripts without a conversion layer.

The donor pipeline (``maverick.donation.TrajectoryRecord``) writes
one record per goal; this schema is the LABELED + STEP-WISE version
of that record, ready for PRM training.

  Record   = one full goal trajectory
  Step     = one (observation, action, reward) tuple inside a Record
  Action   = tool name + args (no return values; those leak PII)
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TrainingStep:
    """One step of an agent trajectory, labeled for PRM training."""
    step_index: int
    role: str
    action_type: str        # "tool_call" | "think" | "spawn" | "final"
    action_name: str        # tool name, or "" for think
    observation_hash: str   # hash of the prior observation (no raw)
    error: str | None = None
    # Per-step labels (PRM training target).
    promise_label: float | None = None
    progress_label: float | None = None


@dataclass
class TrainingTrajectory:
    """One full goal-run, ready for SFT or RL.

    Mirrors donation.TrajectoryRecord at the goal level but adds the
    step-by-step decomposition. Compatible with the
    Klear-AgentForge `--data-format trajectory` reader.
    """
    schema_version: int = 1
    trajectory_id: str = ""
    task_brief_hash: str = ""
    task_family: str | None = None    # benchmark name when known
    model_id: str = ""
    outcome: str = ""
    terminal_reward: float = 0.0
    verifier_confidence: float = 0.0
    disagreement_entropy: float = 0.0
    wall_seconds: float = 0.0
    cost_dollars: float = 0.0
    steps: list[TrainingStep] = field(default_factory=list)


def to_klear_jsonl(traj: TrainingTrajectory) -> dict:
    """Serialize a TrainingTrajectory to a Klear-AgentForge JSONL row.

    Klear's reader expects a flat dict with `id`, `messages`, and
    `rewards` keys. We construct `messages` from the step list and
    `rewards` from the per-step promise+progress labels.
    """
    messages = []
    rewards = []
    for s in traj.steps:
        messages.append({
            "role": s.role,
            "type": s.action_type,
            "name": s.action_name,
            "obs_hash": s.observation_hash,
            "error": s.error,
        })
        rewards.append({
            "step": s.step_index,
            "promise": s.promise_label,
            "progress": s.progress_label,
        })
    return {
        "id": traj.trajectory_id,
        "task_family": traj.task_family,
        "model": traj.model_id,
        "outcome": traj.outcome,
        "terminal_reward": traj.terminal_reward,
        "messages": messages,
        "rewards": rewards,
        "meta": {
            "verifier_confidence": traj.verifier_confidence,
            "disagreement_entropy": traj.disagreement_entropy,
            "wall_seconds": traj.wall_seconds,
            "cost_dollars": traj.cost_dollars,
        },
    }
