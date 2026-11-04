"""Export the proposer-text side-channel (proposer_texts.jsonl) for real DPO.

The donated/ingested corpus is PII-safe (``ingest.py`` hashes observations into
``observation_hash``), so ``rlaif`` needs raw text supplied out-of-band. This
producer reconstructs a real transcript per trajectory FROM YOUR OWN world
model -- the ``goal_events`` stream (plans / observations / findings) carries
the agent's actual content -- keyed by the SAME ``trajectory_id`` that
``ingest.py`` assigns, so the sidecar lines up with ``trajectories.jsonl``.

PRIVACY: this writes your raw run transcripts to a local file (the thing the
shared corpus deliberately avoids). Fine on a GPU box you control; treat
shipping it to a third party as an explicit egress decision.

Usage:

    python -m maverick.training.export_texts \\
        --in ~/.maverick/outbox --out proposer_texts.jsonl

Then feed it to RLAIF/DPO:

    python -m maverick.training.rlaif --data trajectories.jsonl \\
        --text-sidecar proposer_texts.jsonl --require-real-text ...

Fidelity note: ``goal_events`` is the agent's event/blackboard stream, a real
content-bearing proxy for the proposer transcript -- enough for a genuine DPO
signal, but not the literal LLM prompt/response token strings (those are not
persisted by default; capturing them needs a run-time recorder hook).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..paths import data_dir
from .identity import record_trajectory_id
from .ingest import (
    candidate_trajectory_id,
    fetch_steps_for_goal,
    load_donations,
    rejected_trajectory_id,
)


def events_to_text(events: list[dict]) -> str:
    """Join a goal's event stream into a readable transcript (real text).

    Each non-empty event becomes ``[agent/kind] content``; empty events are
    skipped. Returns "" when there is no content (caller drops such rows).
    """
    lines: list[str] = []
    for ev in events or []:
        content = str(ev.get("content") or "").strip()
        if not content:
            continue
        prefix = "/".join(
            p for p in (str(ev.get("agent") or ""), str(ev.get("kind") or "")) if p
        )
        lines.append(f"[{prefix}] {content}" if prefix else content)
    return "\n".join(lines)


def export_texts(records, fetch_events) -> dict[str, str]:
    """Build ``{trajectory_id: transcript}`` from donation records.

    ``fetch_events(record) -> list[event dicts]`` is injected so this is
    testable without a world model. Trajectories with no transcript text are
    omitted (a pair lacking real text is dropped downstream by
    ``rlaif.attach_pair_texts``).

    Also emits the rejected pre-revision drafts (carried IN the record, not the
    world DB) under the ids ``ingest.build_rejected_trajectories`` assigns, so
    the DPO sidecar has real text for BOTH halves of a chosen/rejected pair.
    """
    out: dict[str, str] = {}
    seen: dict[str, str] = {}
    for record in records:
        identity = record_trajectory_id(record)
        binding = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if identity in seen:
            if seen[identity] != binding:
                raise ValueError("Conflicting donation records share a trajectory identity")
            continue
        seen[identity] = binding
        text = events_to_text(fetch_events(record) or [])
        if text:
            out[record_trajectory_id(record)] = text
        for i, att in enumerate(record.get("rejected_attempts", []) or []):
            rej_text = att.get("text") if isinstance(att, dict) else None
            if rej_text and str(rej_text).strip():
                out[rejected_trajectory_id(record, i)] = str(rej_text)
        # Best-of-N candidate patches ride IN the record (not the world DB), so
        # they export even off the origin machine -- keyed by the same id ingest
        # assigns, so rlaif resolves both halves of a candidate pair.
        for i, c in enumerate(record.get("scored_candidates", []) or []):
            cand_text = c.get("text") if isinstance(c, dict) else None
            if cand_text and str(cand_text).strip():
                out[candidate_trajectory_id(record, i)] = str(cand_text)
    return out


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python -m maverick.training.export_texts",
        description="Export proposer_texts.jsonl (raw transcripts) for real DPO.",
    )
    ap.add_argument("--in", dest="in_dir", type=Path, default=data_dir("outbox"),
                    help="Donation outbox dir (default ~/.maverick/outbox).")
    ap.add_argument("--out", dest="out_file", type=Path,
                    default=Path("proposer_texts.jsonl"),
                    help="Output JSONL ({\"id\",\"text\"} per line).")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        from ..world_model import close_world_if_owned, open_world
        world = open_world()
    except Exception:  # pragma: no cover -- world optional; no world -> no text
        world = None
    try:
        records = list(load_donations(args.in_dir, world=world))
        if world is not None:
            def fetch(rec):
                return fetch_steps_for_goal(world, rec.get("goal_id", 0))
        else:
            def fetch(rec):
                return []
        texts = export_texts(records, fetch)
    finally:
        if world is not None:
            close_world_if_owned(world)
    with args.out_file.open("w", encoding="utf-8") as out:
        for tid, text in texts.items():
            out.write(json.dumps({"id": tid, "text": text}) + "\n")
    print(
        f"exported {len(texts)} proposer transcript(s) -> {args.out_file} "
        f"(from {len(records)} donation record(s))", file=sys.stderr,
    )
    if not texts:
        print(
            "WARNING: no transcripts. Did you run goals with [telemetry] "
            "donate_trajectories=true, and is the world DB on this machine?",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
