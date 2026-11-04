"""``maverick immune`` -- discover, prove and remember what policies miss.

Registered on package import. The kernel
surface is :mod:`maverick.immune`; this module only renders it.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import click

from . import _strip_terminal_control, main, open_world


def _load(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise click.ClickException(f"{path}: not readable JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise click.ClickException(f"{path}: expected a JSON object")
    return data


def _emit(obj) -> None:
    click.echo(json.dumps(obj, indent=2, sort_keys=True, default=list))


@main.group("immune")
def immune_group() -> None:
    """Adaptive immunity: composition risk, oversight assurance, discovery title."""


@immune_group.command("network")
@click.option("--graph", "graph_file", type=click.Path(exists=True, dir_okay=False),
              help="Agent graph JSON ({agents: {name: [tools]}, flows: [[a, b]]}). "
                   "Default: the installed pack roster at its runtime capability.")
@click.option("--levels/--no-levels", default=None,
              help="Override autonomy levels (default: this deployment's setting).")
@click.option("--grounding/--no-grounding", default=None,
              help="Override data grounding (default: this deployment's setting).")
@click.option("--swarm", is_flag=True, help="Model packs sharing one swarm (peer messaging).")
@click.option("--json", "as_json", is_flag=True)
@click.option("--limit", default=20, show_default=True, help="Findings to print.")
def network_cmd(graph_file, levels, grounding, swarm, as_json, limit) -> None:
    """Find data paths from sensitive reads to external reach (Rule of Two)."""
    from ..immune import network as n
    if graph_file:
        g = n.load_graph(_load(graph_file))
    else:
        g = n.roster_graph(swarm=swarm, levels=levels, grounding=grounding)
    found = n.findings(g)
    if as_json:
        _emit([f.__dict__ for f in found])
        return
    counts = Counter((f.kind, f.sink_risk) for f in found)
    click.echo(f"{len(g.agents)} agents, {len(found)} findings: "
               + ", ".join(f"{k}/{r} sink={c}" for (k, r), c in sorted(counts.items())))
    for f in found[:limit]:
        w = "; ".join(f"{cls}={a}:{t}" for cls, (a, t) in sorted(f.witness.items()))
        click.echo(f"  {f.kind:<12} {' -> '.join(f.path)}  [{w}]")


@immune_group.command("canary")
@click.option("--action", required=True, help="What the approver sees.")
@click.option("--detail", required=True)
@click.option("--class", "decision_class", required=True, help="e.g. payments, contracts.")
@click.option("--flaw", required=True, help="The known flaw (kept private).")
@click.option("--risk", default="medium", show_default=True)
@click.option("--requested-by", default=None)
@click.option("--acts-at-once", is_flag=True,
              help="Imitate a request that takes effect when decided (a merge, settings change or agent "
                   "access), which offers no Undo. Default: a task's step, which can be undone for a moment.")
def canary_cmd(action, detail, decision_class, flaw, risk, requested_by, acts_at_once) -> None:
    """Seed one known-flawed approval into the real queue ([immune] canaries)."""
    from ..immune import oversight as o
    try:
        aid = o.seed_canary(open_world(), action=action, detail=detail,
                            decision_class=decision_class, flaw=flaw, risk=risk,
                            requested_by=requested_by, undoable=not acts_at_once)
    except PermissionError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"seeded canary approval #{aid}")


@immune_group.command("canary-auto")
@click.option("--class", "decision_class", default=None,
              help="Only model approvals of this action (default: any).")
@click.option("--count", default=1, show_default=True, type=click.IntRange(1, 50))
def canary_auto_cmd(decision_class, count) -> None:
    """Seed canaries modelled on real recent approvals, each with one planted
    flaw. The flaw is kept in the private ledger, not printed, so whoever runs
    this can still be measured fairly."""
    from ..immune import oversight as o
    world = open_world()
    try:
        for _ in range(count):
            out = o.generate_canary(world, decision_class=decision_class)
            click.echo(f"seeded canary approval #{out['approval_id']} "
                       f"({out['decision_class']})")
    except (PermissionError, LookupError) as exc:
        raise click.ClickException(str(exc)) from exc


@immune_group.command("drill")
@click.argument("person")
@click.argument("decision_class")
@click.option("--passed/--failed", required=True)
def drill_cmd(person, decision_class, passed) -> None:
    """Record a no-agent capability drill outcome."""
    from ..immune import oversight as o
    o.record_drill(person, decision_class, passed)
    click.echo("recorded")


@immune_group.command("oversight")
@click.option("--drills", is_flag=True, help="Report drills instead of canaries.")
@click.option("--min-n", default=10, show_default=True)
@click.option("--threshold", default=0.8, show_default=True)
def oversight_cmd(drills, min_n, threshold) -> None:
    """Catch rates and earned authority per person and decision class."""
    from ..immune import oversight as o
    stats = o.score(open_world(), "drill" if drills else "canary")
    if not stats:
        click.echo("no decided canaries or drills yet")
    for (person, cls), s in sorted(stats.items()):
        earned = "earned" if o.authority(s, min_n=min_n, threshold=threshold) else "not earned"
        click.echo(f"  {_strip_terminal_control(person):<24} {_strip_terminal_control(cls):<18} "
                   f"caught {s.caught}/{s.n}  assured {s.assured:.0%}  {earned}")


@immune_group.group("title")
def title_group() -> None:
    """Discovery Title dossiers: conception, priority, verification, coverage."""


@title_group.command("check")
@click.argument("dossier", type=click.Path(exists=True, dir_okay=False))
def title_check(dossier) -> None:
    """List what would not survive scrutiny; exit 1 if anything does not."""
    from ..immune import title as t
    try:
        problems = t.problems(_load(dossier))
    except (KeyError, TypeError, AttributeError) as exc:
        raise click.ClickException(f"malformed dossier: missing or invalid {exc}") from exc
    for p in problems:
        click.echo(f"  - {p}")
    if problems:
        raise SystemExit(1)
    click.echo("no problems found")


@title_group.command("seal")
@click.argument("dossier", type=click.Path(exists=True, dir_okay=False))
@click.option("-o", "--out", type=click.Path(dir_okay=False), required=True)
def title_seal(dossier, out) -> None:
    """Sign a dossier with this deployment's audit identity."""
    from ..immune import title as t
    Path(out).write_text(json.dumps(t.seal(_load(dossier)), indent=2), encoding="utf-8")
    click.echo(f"sealed -> {out}")


@title_group.command("verify")
@click.argument("sealed", type=click.Path(exists=True, dir_okay=False))
@click.option("--pubkey", help="Ed25519 public key hex; default: this deployment's trusted key.")
def title_verify(sealed, pubkey) -> None:
    """Verify a sealed dossier offline; exit 1 if it does not verify."""
    from ..audit.signing import trusted_audit_public_keys
    from ..immune import title as t
    doc = _load(sealed)
    try:
        key = pubkey or trusted_audit_public_keys().get(doc["signature"]["key_id"])
        ok = bool(key) and t.verify(doc, key)
    except (KeyError, TypeError, AttributeError, ValueError):
        ok = False  # a malformed seal is simply one that does not verify
    if not ok:
        raise click.ClickException("dossier does NOT verify")
    click.echo("dossier verifies")


@title_group.command("research")
@click.argument("dossier", type=click.Path(exists=True, dir_okay=False))
@click.argument("runs", nargs=-1, required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--element", "elements", multiple=True,
              help="A claim element these runs' planning decisions shaped (repeatable).")
@click.option("-o", "--out", type=click.Path(dir_okay=False), required=True)
def title_research(dossier, runs, elements, out) -> None:
    """Add governed research runs (their exports) to a dossier: every planning
    decision becomes a conception gate, every pinned input a commitment."""
    from ..immune import title
    try:
        merged = title.add_research_runs(_load(dossier), [_load(r) for r in runs], list(elements))
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise click.ClickException(f"cannot use research run: {exc}") from exc
    Path(out).write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
    added = len(merged["gates"]) - len(_load(dossier).get("gates", []))
    click.echo(f"{added} conception gate(s) added -> {out}")


@immune_group.command("rules")
@click.argument("rules_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--candidate", type=click.Path(exists=True, dir_okay=False),
              help="Candidate rules to compare on --events.")
@click.option("--events", type=click.Path(exists=True, dir_okay=False))
@click.option("--max-extra-friction", default=0, show_default=True)
def rules_cmd(rules_file, candidate, events, max_extra_friction) -> None:
    """Find contradictions in a rule set; optionally replay a candidate against it."""
    from ..immune import policy
    rules = _load(rules_file)["rules"]
    for f, r, when in policy.contradictions(rules):
        click.echo(f"  contradiction: {f} forbids what {r} requires when {when}")
    if candidate:
        if not events:
            raise click.UsageError("--candidate needs --events")
        ok, report = policy.better(_load(candidate)["rules"], rules, _load(events)["events"],
                                   max_extra_friction=max_extra_friction)
        _emit({"promote": ok, **report})


@immune_group.group("twin")
def twin_group() -> None:
    """Production twin: replay a recorded goal against what production saw."""


@twin_group.command("replay")
@click.argument("goal_id", type=int)
@click.option("--max-dollars", default=None, type=float,
              help="Spend cap for the twin run (else [budget] / the runner default).")
@click.option("--tolerance", default=0.8, show_default=True, type=click.FloatRange(0, 1),
              help="Minimum argument similarity to serve a near-identical recorded call.")
def twin_replay(goal_id, max_dollars, tolerance) -> None:
    """Re-run GOAL_ID as a new goal whose tools return the recorded results."""
    from ..immune import twin
    from ..runner import run_goal_in_thread
    from . import _require_llm_key
    _require_llm_key()
    world = open_world()
    try:
        report = twin.replay_goal(
            world, goal_id, lambda gid: run_goal_in_thread(
                gid, max_dollars=max_dollars, **twin.run_kwargs(world.get_goal(gid))),
            tolerance=tolerance)
    except LookupError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        world.close()
    _emit(report)


@twin_group.command("forget")
@click.argument("goal_id", type=int)
def twin_forget(goal_id) -> None:
    """Delete GOAL_ID's recording (retention / erasure). Replay reports, which
    hold counts only, are kept."""
    from ..immune import twin
    click.echo(f"recording for goal #{goal_id} "
               + ("deleted" if twin.forget(goal_id) else "not found"))


@twin_group.command("list")
def twin_list() -> None:
    """Past twin replays (counts only)."""
    from ..immune import _ledger, twin
    for r in _ledger.read(twin.replays_path()):
        if r.get("type") == "awareness_probe":
            continue
        sim = r.get("result_similarity")
        click.echo(f"  #{r['production_goal']} -> #{r['twin_goal']}: {r['twin_status']} "
                   f"(served {r['served']}/{r['recorded']}, "
                   f"approximate {len(r.get('approximate', []))}, unmatched {r['unmatched']}, "
                   f"answer similarity {'n/a' if sim is None else sim})")


@immune_group.command("awareness")
@click.argument("samples", required=False, type=click.Path(exists=True, dir_okay=False))
@click.option("--goals", default=None,
              help="Comma-separated recorded goal ids: replay each twice (unmarked and "
                   "with an evaluation cue) and measure the behaviour gap.")
@click.option("--max-dollars", default=None, type=float, help="Spend cap per replay.")
@click.option("--alpha", default=0.05, show_default=True)
def awareness_cmd(samples, goals, max_dollars, alpha) -> None:
    """Does behaviour change when the model can tell it is being watched?

    With --goals, measured from real runs: each recorded production goal is
    replayed as a twin twice, identical except for an evaluation cue. With
    SAMPLES (JSON {"watched": [bool...], "unwatched": [bool...]}), computed from
    flags you supply."""
    from ..immune.invariance import awareness_gap
    if bool(samples) == bool(goals):
        raise click.UsageError("give exactly one of SAMPLES or --goals")
    if goals:
        from ..immune import twin
        from ..runner import run_goal_in_thread
        from . import _require_llm_key
        _require_llm_key()
        try:
            ids = [int(g) for g in goals.split(",") if g.strip()]
        except ValueError as exc:
            raise click.UsageError("--goals must be comma-separated integers") from exc
        if not ids:
            raise click.UsageError("--goals needs at least one goal id")
        world = open_world()
        try:
            _emit(twin.awareness_probe(
                world, ids, lambda gid: run_goal_in_thread(
                    gid, max_dollars=max_dollars, **twin.run_kwargs(world.get_goal(gid))),
                alpha=alpha))
        except LookupError as exc:
            raise click.ClickException(str(exc)) from exc
        finally:
            world.close()
        return
    data = _load(samples)
    try:
        _emit(awareness_gap([bool(x) for x in data["watched"]],
                            [bool(x) for x in data["unwatched"]], alpha=alpha))
    except (KeyError, ValueError) as exc:
        raise click.ClickException(f"bad samples: {exc}") from exc
