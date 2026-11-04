"""`maverick-evolve` CLI.

Without args, prints how to use the package programmatically. With ``--demo`` it
runs a real continuous-evolution loop against a SYNTHETIC, no-LLM fitness
landscape -- so you can watch the archive accumulate and the best score climb
across rounds without spending tokens. The real path is identical but with an
``agent_factory`` that builds a live Lightwork agent from a config.
"""
from __future__ import annotations

import argparse
import asyncio
import random
from pathlib import Path

from .eval_harness import EvalCase
from .loop import evolve_continuous


def _demo(rounds: int, generations: int) -> int:
    # Synthetic, GRADED landscape (no model): one case per threshold, so fitness
    # rises smoothly with the knob and evolution has a gradient to climb -- a
    # realistic fitness shape, not a flat step. Exercises the full
    # loop/archive/persist machinery deterministically.
    thresholds = [2, 4, 6, 8, 10, 12, 14, 16]
    cases = [EvalCase(prompt=str(t), check=lambda o: o == "GOOD") for t in thresholds]

    def agent_factory(config: dict):
        async def agent(prompt: str) -> str:
            return "GOOD" if config.get("max_swarm_fanout", 0) >= int(prompt) else "BAD"
        return agent

    seed = {"max_swarm_fanout": 4}
    space = {"max_swarm_fanout": ("int", 1, 16)}
    best, history = asyncio.run(evolve_continuous(
        seed, cases, agent_factory,
        rounds=rounds, generations_per_round=generations,
        space=space, rng=random.Random(0),
    ))
    print("continuous evolution (synthetic, no LLM):")
    for h in history:
        print(f"  {h}")
    if best is not None:
        print(f"BEST: score={best.score} config={best.config}")
    return 0


def _load_cases(path: str) -> list[EvalCase]:
    """Load eval cases from a JSON list of {prompt, reference?}.

    A case with ``reference`` is scored by substring containment; without one it
    can't pass (so always provide a reference for live runs).
    """
    import json
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    cases: list[EvalCase] = []
    for item in data:
        if isinstance(item, dict) and item.get("prompt"):
            cases.append(EvalCase(prompt=str(item["prompt"]),
                                  reference=item.get("reference")))
    return cases


def _live(cases_path: str, rounds: int, generations: int, archive_path: str | None) -> int:
    import asyncio

    from .agent_adapter import evolve_live
    from .config_space import default_config

    cases = _load_cases(cases_path)
    if not cases:
        print(f"no usable cases in {cases_path!r} (need a JSON list of {{prompt, reference}})")
        return 2
    print(f"live evolution: {len(cases)} eval case(s), {rounds} round(s) "
          f"x {generations} generations. Each candidate runs `maverick start` "
          "in a subprocess (needs a configured provider/API key).")
    best, history = asyncio.run(evolve_live(
        default_config(), cases,
        rounds=rounds, generations_per_round=generations,
        archive_path=archive_path,
    ))
    for h in history:
        print(f"  {h}")
    if best is not None:
        print(f"BEST: score={best.score} config={best.config}")
    return 0


def _adopt(args) -> int:
    """Print (and with --yes, write) the archive-best overlay onto a pack."""
    from .adopt import adopt_best, plan_adoption
    if not args.archive or not args.pack:
        print("--adopt requires --archive <archive.json> and --pack <pack.toml>")
        return 2
    keys = [k.strip() for k in (args.keys or "").split(",") if k.strip()] or None
    try:
        _, changes = plan_adoption(args.archive, args.pack, keys=keys)
    except (OSError, ValueError) as e:
        print(f"adopt failed: {e}")
        return 2
    if not changes:
        print("archive best changes nothing in this pack; nothing to adopt.")
        return 0
    for key, (old, new) in changes.items():
        print(f"{key}:\n  - {old!r}\n  + {new!r}")
    if not args.yes:
        print("dry run (pass --yes to write the adopted pack; the previous "
              "file is backed up to .bak).")
        return 0
    dest = adopt_best(args.archive, args.pack, keys=keys, out_dir=args.out)
    print(f"adopted -> {dest}")
    return 0


def _live_rehearsals(args) -> int:
    """--live --rehearsals: evolve against the kernel's rehearsal queue."""
    from .rehearsal_bridge import cases_from_rehearsals
    cases = cases_from_rehearsals()
    if not cases:
        if args.cases:
            return _live(args.cases, args.rounds, args.generations, args.archive)
        print("rehearsal queue is empty (run `maverick dream` with "
              "[dreaming] rehearse = true first), and no --cases fallback given.")
        return 2
    import asyncio as _asyncio

    from .agent_adapter import evolve_live
    from .config_space import default_config
    print(f"live evolution against {len(cases)} rehearsal case(s) "
          f"(your own recurring failures), {args.rounds} round(s) "
          f"x {args.generations} generations.")
    best, history = _asyncio.run(evolve_live(
        default_config(), cases,
        rounds=args.rounds, generations_per_round=args.generations,
        archive_path=args.archive,
    ))
    for h in history:
        print(f"  {h}")
    if best is not None:
        print(f"BEST: score={best.score} config={best.config}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="maverick-evolve")
    p.add_argument("--demo", action="store_true",
                   help="Run a no-LLM synthetic continuous-evolution loop.")
    p.add_argument("--live", action="store_true",
                   help="Evolve against REAL runs (each candidate runs `maverick "
                        "start` in a subprocess). Requires --cases and a provider key.")
    p.add_argument("--cases", help="Path to a JSON list of {prompt, reference} eval cases.")
    p.add_argument("--archive", help="Path to persist/resume the evolution archive.")
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--generations", type=int, default=20)
    p.add_argument("--rehearsals", action="store_true",
                   help="With --live: use the kernel's dream-time rehearsal "
                        "queue as the eval cases (evolve against your own "
                        "recurring failures; falls back to --cases when the "
                        "queue is empty).")
    p.add_argument("--adopt", action="store_true",
                   help="Adopt the archive's best config into a domain pack "
                        "(requires --archive and --pack; shows the diff and "
                        "needs --yes to write).")
    p.add_argument("--pack", help="Path to the domain pack TOML to adopt into.")
    p.add_argument("--out", help="Directory to write the adopted pack "
                                 "(default: alongside --pack).")
    p.add_argument("--keys", help="Comma-separated adoptable keys "
                                  "(default: persona,description,models).")
    p.add_argument("--yes", action="store_true",
                   help="Actually write the adopted pack (without it, "
                        "--adopt only prints the planned changes).")
    args = p.parse_args(argv)
    if args.adopt:
        return _adopt(args)
    if args.live:
        if args.rehearsals:
            return _live_rehearsals(args)
        if not args.cases:
            print("--live requires --cases <path-to-cases.json> (or --rehearsals)")
            return 2
        return _live(args.cases, args.rounds, args.generations, args.archive)
    if not args.demo:
        print(
            "maverick-evolve: governed config-evolution.\n"
            "  --demo                         run a no-LLM synthetic evolution loop\n"
            "  --live --cases cases.json      evolve against real `maverick start` runs\n"
            "Programmatic: maverick_evolve.evolve_continuous(seed, cases, agent_factory, ...)"
        )
        return 0
    return _demo(args.rounds, args.generations)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
