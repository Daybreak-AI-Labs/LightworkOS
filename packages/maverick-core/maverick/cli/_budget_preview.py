"""Read-only local task ceilings for native clients; no identity inference."""
from __future__ import annotations

import json

import click

from . import main


@main.command("budget-preview")
@click.option("--max-dollars", type=click.FloatRange(min=0), default=None)
@click.option("--max-wall-seconds", type=click.FloatRange(min=1), default=None)
@click.option("--json", "as_json", is_flag=True, help="Return the structured read-only preview.")
def budget_preview(max_dollars, max_wall_seconds, as_json):
    """Resolve task ceilings in this CLI's current workspace and environment."""
    from ..budget_guidance import preview

    try:
        result = preview(principal=None, max_dollars=max_dollars,
                         max_wall_seconds=max_wall_seconds)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    if as_json:
        click.echo(json.dumps(result, allow_nan=False))
    else:
        effective = result.get("effective") or {}
        click.echo("Resolved local task ceilings: $" + str(effective.get("max_dollars", "unknown"))
                   + ", " + str(effective.get("max_wall_seconds", "unknown")) + " seconds")
        click.echo(str(result.get("notice") or "This preview does not reserve budget. Launch rechecks current policy."))
