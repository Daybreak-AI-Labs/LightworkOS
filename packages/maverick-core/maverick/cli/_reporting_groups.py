"""Analytics, outcomes, and cost-reporting CLI commands.

Registered by importing this module at the end
of the package __init__ so the @main.command decorators fire on package import.

open_world is resolved lazily inside each command that opens the world DB, so
tests that monkeypatch maverick.cli.open_world still reach those commands.
"""
from __future__ import annotations

import click

from . import _strip_terminal_control, main


@main.command("analytics")
@click.option("--sql", default=None, help="Ad-hoc read-only SQL over goals/episodes.")
@click.option("--top", type=int, default=10, help="Top-N costliest goals (default view).")
@click.pass_context
def analytics_cmd(ctx, sql: str | None, top: int) -> None:
    """OLAP analytics over the world model via DuckDB ([duckdb] extra).

    Default view: per-goal cost percentiles + the costliest goals. `--sql`
    runs an ad-hoc SELECT over `goals` and `episodes` (read-only).
    """
    import json as _json

    try:
        from ..duckdb_analytics import WorldAnalytics

        # duckdb imports lazily inside the constructor, so the actionable
        # "python -m pip install -e './packages/maverick-core[duckdb]'" ImportError fires HERE --
        # construction must sit inside the catch or the user gets a raw
        # traceback.
        from . import open_world  # lazy: monkeypatch-reachable
        wa = WorldAnalytics(open_world(ctx.obj["db"]))
    except ImportError as e:
        raise click.ClickException(str(e)) from e
    try:
        if sql:
            click.echo(_json.dumps(wa.query(sql), default=str))
            return
        pct = wa.cost_percentiles()
        click.echo(click.style("Per-goal cost percentiles", bold=True))
        if pct.get("n"):
            click.echo(f"  goals={int(pct['n'])}  p50=${pct['p50']:.2f}  "
                       f"p90=${pct['p90']:.2f}  p99=${pct['p99']:.2f}  "
                       f"max=${pct['max_cost']:.2f}")
        else:
            click.echo("  no priced goals yet.")
        rows = wa.top_goals(top)
        if rows:
            click.echo(click.style("\nCostliest goals", bold=True))
            for r in rows:
                click.echo(f"  #{int(r['id'])} ${r['total_cost']:.2f} "
                           f"({int(r['ep_count'])} ep)  {r['title']}")
    finally:
        wa.close()


@main.command("compounding")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.option("--window", type=int, default=5, help="Cold/warm window per task class.")
@click.pass_context
def compounding(ctx, as_json: bool, window: int) -> None:
    """Does the workforce get cheaper and better with use?

    Per task class, compares the earliest runs (cold) against the most recent
    (warm) and reports the cost and reliability deltas. Read-only.
    """
    import json as _json

    from ..compounding_metric import report_from_world
    from . import open_world  # lazy: monkeypatch-reachable
    world = open_world(ctx.obj["db"])
    reps = report_from_world(world, window=window)
    if as_json:
        click.echo(_json.dumps([r.to_dict() for r in reps]))
        return
    if not reps:
        click.echo("Not enough runs yet to measure compounding "
                   "(need several runs of the same task class).")
        return
    click.echo(click.style("Compounding — cold vs warm by task class", bold=True))
    for r in reps:
        arrow = "improving" if r.improving else "flat/regressing"
        click.echo(
            f"  {r.task_class}: {r.runs} runs  "
            f"cost {r.cost_delta_pct:+.0f}%  success {r.success_delta:+.2f}  [{arrow}]")


@main.command("record-outcome")
@click.argument("goal_id", type=int)
@click.argument("episode_id", type=int)
@click.argument("value", type=float)
@click.option("--kind", default="", help="What the outcome is (e.g. invoice_paid, renewed).")
def record_outcome(goal_id: int, episode_id: int, value: float, kind: str) -> None:
    """Feed a REAL downstream outcome back to a past episode (the grounded reward).

    The Consequence Engine's ingestion entrypoint -- a system-of-record connector
    (or a human) calls this once reality reports back: ``maverick record-outcome
    <goal_id> <episode_id> <value>`` with value in [0,1] (paid=1.0, reopened=0.0,
    or a graded result). The flywheel then prefers this over the verifier proxy
    when it next turns, so learning is grounded in what actually happened.
    """
    from ..consequence import ConsequenceWriteUncertain
    from ..consequence import record_outcome as _rec
    try:
        ok = _rec(goal_id, episode_id, value, kind=kind, source="reported_business")
    except ConsequenceWriteUncertain as exc:
        raise click.ClickException("The report may already be saved. Its outcome is unconfirmed; check it before trying again.") from exc
    if not ok:
        raise click.ClickException("The outcome report was not saved. Review the learning settings and storage availability.")
    click.echo(
        f"recorded outcome {value:g} for goal {goal_id} episode {episode_id}"
        f"{(' (' + kind + ')') if kind else ''}")




@main.command("flywheel")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def flywheel(as_json: bool) -> None:
    """Turn the Cognitive Data Engine flywheel once over the Operating Record.

    One grounded pass: triage production failures by causal impact, mine
    self-correcting guardrails, consolidate beneficial habits into procedural
    memory, and propose process improvements -- learning from REAL outcomes where
    they've reported back. A no-op unless ``[data_engine]`` is enabled.
    """
    import json as _json

    from ..flywheel import maybe_run
    rep = maybe_run()
    if as_json:
        click.echo(_json.dumps({
            "n_episodes": rep.n_episodes,
            "guardrails": [g.to_dict() for g in rep.guardrails],
            "memories": [m.to_dict() for m in rep.memories],
            "hypotheses": [{"swap": f"{h.baseline_action}->{h.candidate_action}",
                            "predicted_lift": h.predicted_lift} for h in rep.hypotheses],
            "predicted_lift": rep.predicted_lift,
            "complete": rep.complete,
            "problem": rep.problem,
        }))
        if not rep.complete:
            raise SystemExit(1)
        return
    if not rep.complete:
        # maybe_run() folds a failed cycle into an empty report; that is not
        # "nothing to learn".
        raise click.ClickException(f"flywheel cycle failed: {rep.problem or 'unknown error'}")
    if not rep.acted:
        click.echo("Flywheel: nothing to learn yet "
                   "(data engine off, or no failures/habits in the corpus).")
        return
    click.echo(click.style(f"Flywheel — one turn over {rep.n_episodes} episodes", bold=True))
    if rep.guardrails:
        click.echo(f"  guardrails learned: {len(rep.guardrails)} "
                   f"(recoverable lift ~{rep.predicted_lift:.2f})")
        for g in rep.guardrails[:5]:
            click.echo(f"    avoid '{g.action}' (severity {g.severity:.2f})")
    if rep.memories:
        click.echo(f"  habits consolidated: {len(rep.memories)}")
        for m in rep.memories[:5]:
            click.echo(f"    prefer '{m.action}' (strength {m.strength:.2f})")
    if rep.hypotheses:
        click.echo(f"  improvements proposed: {len(rep.hypotheses)}")
        for h in rep.hypotheses[:5]:
            click.echo(f"    swap '{h.baseline_action}' -> '{h.candidate_action}' "
                       f"(predicted +{h.predicted_lift:.2f})")


@main.command("cost-retro")
@click.option("--top", type=int, default=10, help="How many costliest goals to show.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def cost_retro(ctx, top: int, as_json: bool) -> None:
    """Cost retrospective: where spend went, and what to do about it.

    Reads recorded per-goal spend and reports the costliest goals, how much
    went to failed work, how concentrated spend is, and actionable
    observations. Read-only.
    """
    import json as _json

    from ..cost.retrospective import retrospective
    from . import open_world  # lazy: monkeypatch-reachable
    world = open_world(ctx.obj["db"])
    rep = retrospective(world, top_n=top)
    if as_json:
        click.echo(_json.dumps(rep))
        return
    click.echo(click.style(
        f"Cost retrospective — ${rep['total_spend']:.2f} across "
        f"{rep['priced_goals']} priced goal(s)", bold=True))
    if rep["failed_spend"]:
        click.echo(f"  failed work: ${rep['failed_spend']:.2f} "
                   f"({rep['failed_share']:.0%})")
    if rep["top_goals"]:
        click.echo(click.style("\nCostliest goals", bold=True))
        for r in rep["top_goals"]:
            flag = " [FAILED]" if r["failed"] else ""
            title = _strip_terminal_control(r["title"])
            click.echo(f"  #{r['goal_id']} ${r['cost']:.2f} "
                       f"({r['episodes']} ep){flag}  {title}")
    click.echo(click.style("\nObservations", bold=True))
    for o in rep["observations"]:
        click.echo(f"  • {o}")


@main.command("charts")
@click.option("--days", type=int, default=7, help="How many days to chart.")
@click.option("--plain", is_flag=True, help="Force plain ASCII (no rich panels).")
@click.pass_context
def charts(ctx, days: int, plain: bool) -> None:
    """Inline terminal charts: spend/day, goal throughput, tool latency.

    Sparklines + bars drawn from recorded data — the usage ledger (spend),
    the world model (done/failed per day), and the tool-latency profile.
    Uses ``rich`` panels when installed; falls back to plain ASCII. Sections
    with no data say so. Read-only.
    """
    from .. import terminal_charts, tool_latency
    from . import open_world  # lazy: monkeypatch-reachable
    world = open_world(ctx.obj["db"])
    report = tool_latency.report()
    if plain:
        click.echo(terminal_charts.render_dashboard(world, None, report, days=days))
        return
    out = terminal_charts.render_dashboard_rich(world, None, report, days=days)
    if isinstance(out, str):
        click.echo(out)
    else:
        from rich.console import Console
        Console().print(out)
