"""``maverick connectors`` -- inspect + preview governed system-of-record writes.

Makes the governed-connector write path operable from the CLI: list the
connectors an operator has registered (``[governed_connectors]``) and SIMULATE a
write to preview its effect + approval requirement WITHOUT committing. Commit is
deliberately not exposed here -- a live system-of-record write needs an approver
and runs through the orchestrator's governed path, not a fire-and-forget CLI.

Registered by import at the end of the package __init__, like the other
``_*_groups`` modules.
"""
from __future__ import annotations

import json as _json

import click

from . import main


def _configured():
    """``(GovernedActions, {name: (read, write)})`` for the configured
    connectors, or a clean ClickException when none are set up."""
    from ..governed_rest import configured_governed_actions
    ga, registered = configured_governed_actions()
    if not registered:
        raise click.ClickException(
            "no governed connectors configured. Enable [governed_connectors] "
            "and list connectors (e.g. salesforce, servicenow), or set "
            "MAVERICK_GOVERNED_CONNECTORS=1.")
    return ga, registered


@main.group("connectors")
def connectors_group() -> None:
    """Inspect + preview governed system-of-record connectors.

    A governed write previews its effect, hits the approval floor
    ([actions] require_approval_at), and records tamper-evident lineage --
    instead of a bare confirm-gated tool call.
    """


@connectors_group.command("list")
def connectors_list_cmd() -> None:
    """List the registered governed connectors and their actions."""
    ga, registered = _configured()
    from ..governed_rest import connector_rows
    click.echo(_json.dumps(connector_rows(ga, registered), indent=2))


@connectors_group.command("simulate")
@click.argument("action")
@click.option("--params", "params_json", default="{}",
              help='Typed params as a JSON object, e.g. '
                   '\'{"op":"post","path":"/x","body":{"Name":"Acme"}}\'.')
def connectors_simulate_cmd(action, params_json) -> None:
    """Preview ACTION's effect WITHOUT committing (simulate-before-commit).

    ACTION is a governed action name like ``salesforce.write``. Prints the
    previewed effect, risk tier, and whether a commit would require an approver.
    """
    ga, _registered = _configured()
    try:
        params = _json.loads(params_json)
        if not isinstance(params, dict):
            raise ValueError("params must be a JSON object")
    except ValueError as e:
        raise click.ClickException(f"invalid --params JSON: {e}") from e
    from ..governed_actions import ActionError
    try:
        preview = ga.simulate(action, params)
    except ActionError as e:
        raise click.ClickException(str(e)) from e
    click.echo(_json.dumps({
        "action": preview.action,
        "effect": preview.effect,
        "risk": preview.risk,
        "requires_approval": preview.requires_approval,
        "committed": False,
    }, indent=2))


@connectors_group.command("plan")
@click.argument("connector")
@click.option("--params", "params_json", default="{}",
              help='Typed write params as a JSON object, e.g. '
                   '\'{"op":"patch","path":"/services/data/v60.0/sobjects/'
                   'Opportunity/006xx0000000001AAA","body":{"Amount":120000}}\'.')
def connectors_plan_cmd(connector, params_json) -> None:
    """Show the structured consequence of a write, and whether it can be undone.

    Unlike ``simulate`` (which never touches the network), planning may issue
    ONE read-only GET to read the record's prior values -- that captured
    restore point is what earns ``reversible: true``. It performs no write.
    """
    _ga, registered = _configured()
    name = str(connector).strip().lower()
    if name not in {str(k).strip().lower() for k in registered}:
        raise click.ClickException(
            f"{connector!r} is not a registered governed connector "
            f"(have: {', '.join(sorted(registered)) or 'none'})")
    try:
        params = _json.loads(params_json)
        if not isinstance(params, dict):
            raise ValueError("params must be a JSON object")
    except ValueError as e:
        raise click.ClickException(f"invalid --params JSON: {e}") from e
    from ..connector_previews import plan_write
    from ..governed_rest import GOVERNED_REST_FACTORIES
    plan = plan_write(GOVERNED_REST_FACTORIES[name](), params)
    click.echo(_json.dumps({
        **plan.preview.card_view(),
        "restore": {"kind": plan.restore.kind, "entity": plan.restore.entity,
                    "captured": plan.restore.captured,
                    "detail": plan.restore.detail},
        "warnings": list(plan.warnings),
        "committed": False,
    }, indent=2))
