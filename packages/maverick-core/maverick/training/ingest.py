"""Ingest donated trajectories into the training schema.

Reads ``~/.maverick/outbox/*.json`` (written by
``maverick.donation.write_record``) + the matching goal_events from
the world model, produces ``TrainingTrajectory`` objects, then writes
Klear-format JSONL for downstream training.

Usage:

    python -m maverick.training.ingest --in ~/.maverick/outbox \\
        --out trajectories.jsonl

Selection: only trajectories already on the gold list (the donation
selector gates on disagreement_high + outcome=success + verifier_conf
≥ 0.75) make it to the outbox in the first place. Ingest doesn't
re-filter; it labels.

Labels: HeuristicPRM labels per step (no human-in-loop needed). When
real labels are available (operator graded the run via thumbs / test
pass), those override the heuristic ones.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Iterator
from pathlib import Path

from ..paths import data_dir
from ..prm import HeuristicPRM, StepContext
from .identity import record_trajectory_id
from .schema import TrainingStep, TrainingTrajectory, to_klear_jsonl

log = logging.getLogger(__name__)


def load_donations(outbox: Path, *, world=None) -> Iterator[dict]:
    """Yield each donated record (raw dict) from the outbox directory."""
    if not outbox.exists():
        return
    for p in sorted(outbox.glob("*.json")):
        try:
            record = json.loads(p.read_text(encoding="utf-8"))
            from ..memory_ownership import source_allowed
            if (isinstance(record, dict) and record.get("source_ownership") == "unowned"
                    and source_allowed(record.get("goal_id"), "", world=world)):
                yield record
        except json.JSONDecodeError:
            continue


def fetch_steps_for_goal(world, goal_id: int) -> list[dict]:
    """Pull ALL goal_events for a goal from the world model.

    Returns dicts; the world is optional (donations may have been pruned before
    ingestion). Paginates past ``goal_events``' default limit (200) so a long
    trajectory isn't silently truncated -- a truncated trajectory is corrupt
    training data. A real DB error therefore raises ``RuntimeError`` instead of
    returning the events read so far as if they were the whole trajectory.
    """
    if world is None:
        return []
    from ..pilot_learning import excluded
    if excluded(goal_id):
        return []
    from ..memory_ownership import source_allowed
    if not source_allowed(goal_id, "", world=world):
        return []
    out: list[dict] = []
    since = 0
    try:
        while True:
            batch = world.goal_events(goal_id, since_id=since, limit=500)
            if not batch:
                break
            for e in batch:
                out.append({"agent": e.agent, "kind": e.kind,
                            "content": e.content, "ts": e.ts})
            if len(batch) < 500:
                break
            since = batch[-1].id  # continue after the last event id
        return out
    except Exception as e:
        raise RuntimeError(
            f"ingest: goal_events({goal_id}) lookup failed after {len(out)} event(s); "
            "refusing to train on a truncated trajectory"
        ) from e


def build_trajectory(
    record: dict,
    events: list[dict],
    *,
    prm=None,
) -> TrainingTrajectory:
    """Convert a (donation record, goal_events) pair into a labeled
    TrainingTrajectory."""
    prm = prm or HeuristicPRM()
    steps: list[TrainingStep] = []
    prior_promise = 0.5
    for i, ev in enumerate(events):
        kind = ev.get("kind", "")
        action_type = {
            "plan": "think",
            "observation": "tool_call",
            "finding": "final",
            "verify": "think",
            "error": "tool_call",
        }.get(kind, "think")
        content = (ev.get("content") or "")[:200]
        error = content if kind == "error" else None
        tool_name = ""
        # observation lines come in as "tool=NAME -> ...".
        if kind == "observation" and content.startswith("tool="):
            tool_name = content.split(" ", 1)[0].split("=", 1)[1]
        is_final = kind == "finding"

        ctx = StepContext(
            goal_id=0, step_index=i, role=ev.get("agent", "").split("-")[0],
            tool_name=tool_name or None,
            tool_succeeded=(error is None) if action_type == "tool_call" else None,
            is_final=is_final, error=error,
            prior_step_score=prior_promise,
        )
        reward = prm.score(ctx)
        prior_promise = reward.promise

        # Hash the observation so we don't leak content into training.
        import hashlib
        obs_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

        steps.append(TrainingStep(
            step_index=i,
            role=ctx.role,
            action_type=action_type,
            action_name=tool_name,
            observation_hash=obs_hash,
            # Export the HASH, not raw error text: for kind=="error" the error
            # IS the raw content, so storing it verbatim leaked content into
            # exported training data, defeating the observation-hash privacy
            # protection. (ctx.error above stays raw -- local scoring only.)
            error=(obs_hash if kind == "error" else None),
            promise_label=reward.promise,
            progress_label=reward.progress,
        ))

    return TrainingTrajectory(
        trajectory_id=record_trajectory_id(record),
        task_brief_hash=record.get("task_brief_hash", ""),
        # DPO pairs are built WITHIN a task_family (build_preference_pairs skips
        # any row whose family is empty). Repeated attempts at the same task
        # share a task_brief_hash, so it IS the family key -- without this every
        # ingested row had task_family=None and pairing produced 0 pairs no
        # matter how the rewards differed.
        task_family=record.get("task_brief_hash") or None,
        model_id=record.get("model_id", ""),
        outcome=record.get("outcome", ""),
        terminal_reward=record.get("reward", 0.0),
        verifier_confidence=record.get("verifier_confidence", 0.0),
        disagreement_entropy=record.get("disagreement_entropy", 0.0),
        wall_seconds=record.get("wall_seconds", 0.0),
        cost_dollars=record.get("cost_dollars", 0.0),
        steps=steps,
    )


def rejected_trajectory_id(record: dict, i: int) -> str:
    """Id for the i-th rejected draft of a record. Shares the chosen row's
    prefix (so export_texts can key the sidecar text to it) with a ``-rej{i}``
    suffix to keep it a distinct row in the same task_family."""
    base = record_trajectory_id(record)
    return f"{base}-rej{i}"


def build_rejected_trajectories(record: dict) -> list[TrainingTrajectory]:
    """One low-reward TrainingTrajectory per rejected pre-revision draft.

    These pair against the record's chosen (accepted) trajectory WITHIN the same
    task_family: chosen reward ~1.0 vs the rejected draft's verifier confidence
    (un-clamped, e.g. 0.62) is the pair's margin. ``rlaif`` keeps only pairs at
    or above its ``min_margin`` (default 0.5), so with the defaults that 0.38
    example is dropped and only drafts scored below ~0.5 pair. Steps are empty -- the
    PRM learns from the accepted run; these exist purely to form preference
    pairs. Drafts without text are skipped (nothing for the DPO sidecar to use).
    """
    out: list[TrainingTrajectory] = []
    for i, att in enumerate(record.get("rejected_attempts", []) or []):
        if not isinstance(att, dict) or not att.get("text"):
            continue
        conf = float(att.get("confidence", 0.0) or 0.0)
        out.append(TrainingTrajectory(
            trajectory_id=rejected_trajectory_id(record, i),
            task_brief_hash=record.get("task_brief_hash", ""),
            task_family=record.get("task_brief_hash") or None,
            model_id=record.get("model_id", ""),
            outcome="rejected",
            terminal_reward=conf,
            verifier_confidence=conf,
            disagreement_entropy=record.get("disagreement_entropy", 0.0),
            steps=[],
        ))
    return out


def candidate_trajectory_id(record: dict, i: int) -> str:
    """Id for the i-th best-of-N candidate of a record. Shares the chosen row's
    prefix (so export_texts can key the sidecar patch to it) with a ``-cand{i}``
    suffix, keeping it a distinct row in the same task_family. Mirrors
    :func:`rejected_trajectory_id`; MUST stay in sync with export_texts."""
    base = record_trajectory_id(record)
    return f"{base}-cand{i}"


def build_candidate_trajectories(record: dict) -> list[TrainingTrajectory]:
    """One TrainingTrajectory per best-of-N candidate, rewarded by its OBJECTIVE
    local-test score (NOT the LLM verifier).

    All candidates share the record's task_family, so a passing candidate
    (terminal_reward ~1.0) and a failing one (~0.0) pair WITHIN the family with a
    ~1.0 margin -- the genuine preference gradient. Steps are empty (DPO-only
    rows). Candidates without text are skipped (no patch for the DPO sidecar).
    """
    out: list[TrainingTrajectory] = []
    for i, c in enumerate(record.get("scored_candidates", []) or []):
        if not isinstance(c, dict) or not c.get("text"):
            continue
        score = float(c.get("score", 0.0) or 0.0)
        out.append(TrainingTrajectory(
            trajectory_id=candidate_trajectory_id(record, i),
            task_brief_hash=record.get("task_brief_hash", ""),
            task_family=record.get("task_brief_hash") or None,
            model_id=record.get("model_id", ""),
            outcome="candidate",
            terminal_reward=score,
            verifier_confidence=score,
            disagreement_entropy=record.get("disagreement_entropy", 0.0),
            steps=[],
        ))
    return out


def klear_rows(outbox: Path, world=None) -> Iterator[dict]:
    """Every donated record in ``outbox`` as Klear-format rows: the accepted
    run, then its rejected pre-revision drafts as extra low-reward rows in the
    same task_family (so DPO can pair them against the accepted run), then its
    best-of-N candidates scored by objective tests (so a passing vs failing
    candidate pairs within the task_family). ``world`` (optional) supplies the
    goal_events; donations may have been pruned before ingestion."""
    for record in load_donations(outbox, world=world):
        events = (
            fetch_steps_for_goal(world, record.get("goal_id", 0))
            if world else []
        )
        yield to_klear_jsonl(build_trajectory(record, events))
        for rej in build_rejected_trajectories(record):
            yield to_klear_jsonl(rej)
        for cnd in build_candidate_trajectories(record):
            yield to_klear_jsonl(cnd)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--in", dest="in_dir", type=Path,
        default=data_dir("outbox"),
        help="Donation outbox dir (default ~/.maverick/outbox)",
    )
    ap.add_argument(
        "--out", dest="out_file", type=Path,
        default=Path("trajectories.jsonl"),
        help="Output JSONL path (Klear format)",
    )
    args = ap.parse_args()

    try:
        from ..world_model import close_world_if_owned, open_world
        world = open_world()
    except Exception:
        world = None

    count = 0
    try:
        with args.out_file.open("w", encoding="utf-8") as out:
            for row in klear_rows(args.in_dir, world):
                out.write(json.dumps(row) + "\n")
                count += 1
    finally:
        if world is not None:
            close_world_if_owned(world)
    print(f"ingested {count} trajectories -> {args.out_file}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
