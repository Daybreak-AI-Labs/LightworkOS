"""Agent Control Plane CLI group: the operator console without the dashboard.

``maverick control-plane status|list|ledger`` read; ``suspend|resume|contain|
release|attenuate|halt|clear-halt`` act (and refuse while ``[control_plane]
enable`` is off). Registered by importing this
module at the end of the package __init__ so the @main.group decorator fires
on package import.
"""
from __future__ import annotations

import json

import click

from . import main


def _actor() -> str:
    import getpass
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:  # pragma: no cover -- no passwd entry (containers)
        return "cli"


def _echo_result(result) -> None:
    """Print a verb's outcome and exit non-zero when it did not fully land."""
    mark = click.style("ok", fg="green") if result.ok else click.style("FAILED", fg="red")
    click.echo(f"{result.verb} {result.principal}: {mark} -- {result.detail}")
    for note in result.notes:
        click.echo(f"  note: {note}")
    if not result.ok:
        raise SystemExit(1)


def _run(fn, *args, **kwargs):
    from .. import agent_control_plane as acp
    try:
        return fn(*args, **kwargs)
    except acp.ControlPlaneError as e:
        raise click.ClickException(str(e)) from e
    except (ValueError, LookupError) as e:
        raise click.ClickException(str(e)) from e


@main.group("control-plane")
def control_plane_group() -> None:
    """Govern every agent from one console: native runs and external agents.

    One roster over the principals the runtime already enforces, and one set
    of verbs whose effects are the stores it already consults -- the
    capability revocation registry, the external trust registry, the security
    plane's containment and the local deployment killswitch. Reads work always; the
    verbs need ``[control_plane] enable = true`` (or MAVERICK_CONTROL_PLANE=1).
    """


@control_plane_group.command("status")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def cp_status(as_json: bool) -> None:
    """Plane on/off, observed halt state, and governed-principal counts."""
    from .. import agent_control_plane as acp
    st = acp.status()
    if as_json:
        click.echo(json.dumps(st, indent=2, sort_keys=True, default=str))
        return
    on = click.style("enabled", fg="green") if st["enabled"] else click.style("off", fg="yellow")
    halted = click.style("HALTED", fg="red") if st["halted"] else "running"
    click.echo(f"control plane: {on}   observed halt: {halted}   "
               f"trust plane: {'enforced' if st['trust_enforced'] else 'open'}")
    n, x = st["native"], st["external"]
    click.echo(f"  native   : {n['principals']} principal(s), {n['running_goals']} running "
               f"goal(s), {n['suspended']} suspended, {n['contained']} contained")
    click.echo(f"  external : {x['agents']} agent(s), {x['active']} active, "
               f"{x['suspended']} suspended, {x['contained']} contained")


@control_plane_group.command("list")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def cp_list(as_json: bool) -> None:
    """The roster: principal, kind, state, running goals, ceilings."""
    from .. import agent_control_plane as acp
    rows = acp.roster()
    if as_json:
        click.echo(json.dumps([r.to_dict() for r in rows], indent=2, sort_keys=True))
        return
    if not rows:
        click.echo("(no governed principals: nothing is running and no external "
                   "agent is registered)")
        return
    for r in rows:
        colour = {"running": "green", "active": "green", "suspended": "red",
                  "contained": "red"}.get(r.state, "yellow")
        ceiling = ""
        if r.kind == acp.KIND_EXTERNAL:
            ceiling = (f"  risk<={r.max_risk or '-'} ${r.max_dollars if r.max_dollars is not None else '-'}"
                       f"  deny={','.join(r.deny_tools) or '-'}")
        click.echo(f"  {r.principal:32} {r.kind:8} [{click.style(r.state, fg=colour)}]"
                   f"  goals={r.running_goals}{ceiling}")


@control_plane_group.command("suspend")
@click.argument("principal")
@click.option("--reason", required=True, help="Why (submitted to the audit log).")
def cp_suspend(principal: str, reason: str) -> None:
    """Revoke PRINCIPAL: its next tool call is denied. Reversible with resume."""
    from .. import agent_control_plane as acp
    _echo_result(_run(acp.suspend, principal, reason=reason, actor=_actor()))


@control_plane_group.command("resume")
@click.argument("principal")
def cp_resume(principal: str) -> None:
    """Lift an ordinary suspend; contained principals require release."""
    from .. import agent_control_plane as acp
    _echo_result(_run(acp.resume, principal, actor=_actor()))


@control_plane_group.command("contain")
@click.argument("principal")
@click.option("--reason", required=True, help="Why (submitted to the audit log).")
def cp_contain(principal: str, reason: str) -> None:
    """Security-plane containment: revoke the subtree and record the incident."""
    from .. import agent_control_plane as acp
    _echo_result(_run(acp.contain, principal, reason=reason, actor=_actor()))


@control_plane_group.command("release")
@click.argument("principal")
def cp_release(principal: str) -> None:
    """Undo a containment (and an external agent's gateway containment)."""
    from .. import agent_control_plane as acp
    _echo_result(_run(acp.release, principal, actor=_actor()))


@control_plane_group.command("attenuate")
@click.argument("principal")
@click.option("--deny-tool", "deny_tools", multiple=True, help="Add a denied tool.")
@click.option("--max-risk", type=click.Choice(["low", "medium", "high"]), default=None)
@click.option("--max-dollars", type=float, default=None)
@click.option("--max-wall-seconds", type=float, default=None)
def cp_attenuate(principal: str, deny_tools: tuple[str, ...], max_risk: str | None,
                 max_dollars: float | None, max_wall_seconds: float | None) -> None:
    """Narrow an external agent's ceiling (never widens; refused whole otherwise)."""
    from .. import agent_control_plane as acp
    _echo_result(_run(
        acp.attenuate, principal, deny_tools=deny_tools, max_risk=max_risk,
        max_dollars=max_dollars, max_wall_seconds=max_wall_seconds, actor=_actor()))


@control_plane_group.command("halt")
@click.option("--reason", required=True, help="Why (submitted to the audit log).")
def cp_halt(reason: str) -> None:
    """Arm the durable local HALT file for this deployment."""
    from .. import agent_control_plane as acp
    _echo_result(_run(acp.halt_all, reason, actor=_actor()))


@control_plane_group.command("clear-halt")
def cp_clear_halt() -> None:
    """Clear this deployment's local HALT file and in-process halt."""
    from .. import agent_control_plane as acp
    _echo_result(_run(acp.clear_halt, actor=_actor()))


@control_plane_group.command("ledger")
@click.argument("principal")
@click.option("--limit", type=int, default=50, show_default=True)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def cp_ledger(principal: str, limit: int, as_json: bool) -> None:
    """The principal's recorded forensic timeline."""
    from .. import agent_control_plane as acp
    rows = _run(acp.ledger, principal, limit=limit)
    if as_json:
        click.echo(json.dumps(rows, indent=2, sort_keys=True, default=str))
        return
    if not rows:
        click.echo(f"(no security events recorded for {principal})")
        return
    for d in rows:
        click.echo(f"  {d['ts']:.0f}  {d['severity']:8} {d['kind']:28} {d['detail']}")
