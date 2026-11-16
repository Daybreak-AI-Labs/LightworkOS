"""``maverick decisions``: answer the decisions runs are waiting for.

The CLI runs on the host with direct access to the database, so it answers
as a workspace administrator. The person who started a run from this host
counts as its starter, so the self-approval rule still applies to them.
"""
from __future__ import annotations

import click

from . import main, open_world


def _cli_actor() -> str:
    from ._agent_control_plane_groups import _actor

    return _actor()


@main.group("decisions")
def decisions() -> None:
    """Decisions runs are waiting for: list and answer them."""


@decisions.command("list")
@click.pass_context
def list_decisions(ctx) -> None:
    """Show the decisions waiting for a person."""
    from .. import decision_requests as dr

    world = open_world(ctx.obj["db"])
    dr.expire_due(world)
    waiting = dr.list_open(world)
    if not waiting:
        click.echo("No decisions are waiting.")
        return
    for d in waiting:
        click.echo(f"#{d.id}  task #{d.goal_id}  {d.area_label}: {d.question}")
        for number, option in enumerate(d.options, 1):
            mark = "  (recommended)" if number == d.recommended else ""
            click.echo(f"    {number}. {option['label']}{mark}: {option['effect']}")
        click.echo(f"    Why: {d.reason}")
        if d.admin_required:
            click.echo("    Needs a workspace administrator.")


@decisions.command("answer")
@click.argument("decision_id", type=int)
@click.argument("option", type=int)
@click.option("--note", default="", help="A note for the run (optional).")
@click.pass_context
def answer_decision(ctx, decision_id: int, option: int, note: str) -> None:
    """Choose OPTION (its number) for decision DECISION_ID."""
    from .. import decision_requests as dr

    world = open_world(ctx.obj["db"])
    current = dr.get(world, decision_id)
    if current is None:
        raise click.ClickException(f"No decision #{decision_id}. See `maverick decisions list`.")
    # A run started from this host has no named owner: this person started it.
    who = _cli_actor() if current.requested_by else ""
    try:
        outcome = dr.answer(world, decision_id, option, actor=who, is_admin=True, note=note,
                            channel="cli", recorded_as=_cli_actor())
    except dr.DecisionRefused as exc:
        raise click.ClickException(exc.message) from exc
    label = (outcome["decision"].option(option) or {}).get("label", "")
    click.echo(f"You chose “{label}” for decision #{decision_id}.")
    if outcome["resume"]:
        click.echo(f"The run is ready to continue. Start it with: maverick resume {current.goal_id}")
    else:
        click.echo("The run continues once nothing else is waiting.")


@decisions.command("expire")
@click.pass_context
def expire_decisions(ctx) -> None:
    """Stop runs whose decision waited past its time (safe to schedule)."""
    from .. import decision_requests as dr

    expired = dr.expire_due(open_world(ctx.obj["db"]))
    click.echo(f"{len(expired)} decision{'s' if len(expired) != 1 else ''} expired.")
