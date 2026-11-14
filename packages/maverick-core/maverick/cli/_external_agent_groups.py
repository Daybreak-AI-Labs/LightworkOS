"""Bring-your-own-agent gateway CLI group: enroll, credentials, admin.

Everything the External Agents dashboard page does, as CLI verbs — so a
headless or air-gapped install can manage enrollment without the dashboard.
Registered by importing this module at the end
of the package __init__ so the @main.group decorators fire on package import.
"""
from __future__ import annotations

import click

from . import main


def _when(ts) -> str:
    """A unix timestamp rendered for operators (UTC), '-' when absent."""
    if not ts:
        return "-"
    import datetime
    return datetime.datetime.fromtimestamp(
        float(ts), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _spend_vs_cap(row: dict) -> str:
    """``$spent/$cap period`` — the meter the budget cutoff actually reads."""
    cap = row.get("max_dollars")
    cap_txt = f"${cap:,.2f}" if cap is not None else "no-cap"
    return f"${row.get('period_spent') or 0.0:,.2f}/{cap_txt} " \
           f"{row.get('period', 'total')}"


@main.group("external-agents")
def external_agents_group() -> None:
    """Govern agents built on OTHER platforms (the bring-your-own-agent gateway).

    An Agentforce, Bedrock, Copilot Studio, OpenAI, LangChain, or custom agent
    runs on its own runtime; enrollment here registers its trust entry (tool /
    risk / budget ceilings), its fleet-memory roster row, and the platform
    provenance the roster shows. These commands are the headless console for
    installs without the dashboard. The ingest/screen plane itself is enabled
    via ``[external_agents] enable`` or ``MAVERICK_EXTERNAL_AGENTS=1``;
    enrollment, credentials, and roster reads work either way."""


@external_agents_group.command("list")
def xa_list_cmd() -> None:
    """The enrolled roster (id, platform, department, lifecycle, spend, runs)."""
    from .. import external_agents as xa
    rows = xa.roster()
    if not rows:
        click.echo("(no external agents enrolled)")
        return
    for r in rows:
        state = click.style("active", fg="green") if r["active"] else \
            click.style(r["lifecycle"], fg="red")
        flags = ""
        if r["contained"]:
            flags += "  " + click.style("CONTAINED", fg="red")
        if r["over_budget"]:
            flags += "  " + click.style("over-budget", fg="yellow")
        click.echo(f"  {r['id']:24}  {r['platform_label']:26}  "
                   f"dept={r['department'] or '-':12}  "
                   f"{_spend_vs_cap(r):24}  runs={r['runs']:<5} "
                   f"[{state}]{flags}")


@external_agents_group.command("enroll")
@click.argument("agent_id")
@click.argument("platform")
@click.option("--description", default="", help="What this agent does.")
@click.option("--owner", default="", help="Human owner (email or name).")
@click.option("--department", default="", help="Department the agent serves.")
@click.option("--allow-tool", multiple=True, metavar="NAME[:RISK]",
              help="Allowed tool; ':low|:medium|:high' pins YOUR risk rating "
                   "for it (floors whatever the agent later declares). "
                   "Repeatable.")
@click.option("--deny-tool", multiple=True, help="Denied tool. Repeatable.")
@click.option("--max-risk", type=click.Choice(["low", "medium", "high"]),
              default=None, help="Risk ceiling for screened actions.")
@click.option("--max-dollars", type=float, default=None,
              help="Reported-spend ceiling (see --budget-period).")
@click.option("--budget-period", type=click.Choice(["monthly", "total"]),
              default=None,
              help="Whether the spend cap resets each calendar month (UTC) "
                   "or is a lifetime cap. When omitted, a new agent gets "
                   "monthly and a re-enrolled agent keeps its current period.")
@click.option("--max-wall-seconds", type=float, default=None,
              help="Wall-clock ceiling per run (violations are flagged).")
@click.option("--data-scope", multiple=True,
              help="Memory data scope the agent may read. Repeatable.")
@click.option("--expires-days", type=float, default=None,
              help="Auto-expire the trust entry after this many days.")
def xa_enroll_cmd(agent_id, platform, description, owner, department,
                  allow_tool, deny_tool, max_risk, max_dollars, budget_period,
                  max_wall_seconds, data_scope, expires_days) -> None:
    """Enroll AGENT_ID (running on PLATFORM) across every plane in one call.

    PLATFORM is where the agent actually runs: agentforce, bedrock, copilot,
    openai, langchain, or custom. Enrollment creates/replaces the managed
    trust entry, registers the fleet-memory roster row when that plane is on,
    and stamps ownership metadata. Re-enrolling the same id updates the
    ceilings but preserves the spend meters and never lifts a containment."""
    from .. import external_agents as xa
    try:
        out = xa.enroll(
            agent_id, platform, description=description, owner=owner,
            department=department, allow_tools=list(allow_tool),
            deny_tools=list(deny_tool), max_risk=max_risk,
            max_dollars=max_dollars, max_wall_seconds=max_wall_seconds,
            data_scopes=list(data_scope), expires_days=expires_days,
            budget_period=budget_period, enrolled_by="cli")
    except xa.ExternalAgentsError as e:
        raise click.ClickException(str(e)) from e
    click.echo(click.style(f"enrolled {out['id']!r}", fg="green")
               + f"  platform={out['platform']}  trust={out['trust']}  "
                 f"fleet_memory={out['fleet_memory']}")
    if out.get("expires_at"):
        click.echo(f"expires: {_when(out['expires_at'])}")
    click.echo("next: `maverick external-agents mint "
               f"{out['id']}` to issue its bearer credential")


@external_agents_group.command("mint")
@click.argument("agent_id")
@click.option("--surface", type=click.Choice(["rest", "a2a", "grpc", "mcp"]),
              default="rest", show_default=True,
              help="Which credential surface the bearer authenticates.")
@click.option("--approval-id", type=int, default=None,
              help="Replay a step-up mint approval ([external_agents] "
                   "mint_approval); one approval mints exactly one token.")
def xa_mint_cmd(agent_id: str, surface: str, approval_id: int | None) -> None:
    """Mint (or rotate) AGENT_ID's bearer token for one surface.

    The token is printed exactly once, below; it is stored for verification
    but no read path ever returns it again. Minting again rotates it (the
    old bearer stops working immediately). With ``[external_agents]
    mint_approval`` on, the first run parks an approval and stops; re-run
    with --approval-id once a decision-maker approves it."""
    from .. import external_agents as xa
    try:
        token = xa.mint_token(agent_id, surface, mint_approval_id=approval_id)
    except xa.MintApprovalPending as e:
        click.echo(click.style(f"approval required — parked as approval "
                               f"#{e.approval_id}", fg="yellow"))
        raise click.ClickException(
            f"{e} — e.g. `maverick external-agents mint {agent_id} "
            f"--surface {surface} --approval-id {e.approval_id}`") from e
    except xa.ExternalAgentsError as e:
        raise click.ClickException(str(e)) from e
    click.echo(click.style(
        f"{surface} token for {agent_id!r} — shown once, store it now; "
        "it cannot be read back:", fg="yellow"))
    click.echo(token)


@external_agents_group.command("show")
@click.argument("agent_id")
def xa_show_cmd(agent_id: str) -> None:
    """One agent's enrollment, ceilings, meters, and Operating Record trail."""
    from .. import external_agents as xa
    try:
        d = xa.agent_detail(agent_id)
    except xa.ExternalAgentsError as e:
        raise click.ClickException(str(e)) from e
    state = click.style("active", fg="green") if d["active"] else \
        click.style(d["lifecycle"], fg="red")
    click.echo(f"id:              {d['id']}")
    click.echo(f"platform:        {d['platform_label']} ({d['platform']})")
    click.echo(f"description:     {d['description'] or '-'}")
    click.echo(f"owner:           {d['owner'] or '-'}")
    click.echo(f"department:      {d['department'] or '-'}")
    click.echo(f"enrolled:        {_when(d['enrolled_at'])}")
    click.echo(f"lifecycle:       {state}")
    click.echo(f"max_risk:        {d['max_risk'] or 'any'}")
    click.echo(f"budget:          {_spend_vs_cap(d)}"
               + (click.style("  OVER BUDGET", fg="yellow")
                  if d["over_budget"] else ""))
    click.echo(f"lifetime spend:  ${d['spent_dollars']:,.2f} over "
               f"{d['runs']} run(s), last {_when(d['last_run_at'])}")
    click.echo("contained:       "
               + (click.style("YES — release with `maverick external-agents "
                              "release`", fg="red")
                  if d["contained"] else "no"))
    click.echo(f"wall violations: {d['wall_violations']}")
    risks = ", ".join(f"{t}={r}" for t, r in sorted(d["tool_risks"].items()))
    click.echo(f"tool risks:      {risks or '-'}")
    click.echo(f"credentials:     {', '.join(d['credentials']) or '(none minted)'}")
    rec = d.get("record") or {}
    click.echo(f"record:          ${rec.get('dollars') or 0.0:,.2f}  "
               f"{rec.get('input_tokens') or 0} in / "
               f"{rec.get('output_tokens') or 0} out tokens")
    memory = ", ".join(f"{k}={v}" for k, v in sorted(d["memory"].items()))
    click.echo(f"memory:          {memory or '-'}")
    if d["episodes"]:
        click.echo("recent episodes:")
        for e in d["episodes"]:
            click.echo(f"  goal #{e['goal_id']:<6} {e['outcome'] or '?':8} "
                       f"${e['cost_dollars'] or 0.0:,.2f}  "
                       f"{_when(e['ended_at'])}")
    else:
        click.echo("recent episodes: (none)")


@external_agents_group.command("revoke")
@click.argument("agent_id")
def xa_revoke_cmd(agent_id: str) -> None:
    """Revoke AGENT_ID's trust entry now (denied even mid-run); keeps the
    enrollment so `restore` can lift it."""
    from .. import agent_trust
    if not agent_trust.lookup(agent_id):
        raise click.ClickException(f"no trust entry for {agent_id!r} — is it "
                                   "enrolled?")
    if agent_trust.set_revoked(agent_id, True):
        click.echo(click.style(f"revoked {agent_id!r}", fg="yellow"))
    else:
        raise click.ClickException(
            f"{agent_id!r} is defined in the server's config file, not in "
            "the managed registry — set revoked = true in [agent_trust], or "
            "re-enroll the same id so the managed entry overrides it")


@external_agents_group.command("restore")
@click.argument("agent_id")
def xa_restore_cmd(agent_id: str) -> None:
    """Lift a revocation on AGENT_ID (managed entries only)."""
    from .. import agent_trust
    from ..revocation import ProtectedRevocationError, shared

    try:
        restored = shared().run_if_unprotected(
            f"agent:{agent_id}",
            lambda: agent_trust.set_revoked(agent_id, False),
        )
    except ProtectedRevocationError as exc:
        raise click.ClickException(
            "agent is security-contained; use `maverick control-plane release`"
        ) from exc
    except Exception as exc:
        raise click.ClickException(
            "containment authority is unavailable; restore refused"
        ) from exc
    if restored:
        click.echo(click.style(f"restored {agent_id!r}", fg="green"))
    else:
        raise click.ClickException(
            f"{agent_id!r} is not in the managed registry (a config-file "
            "entry must be edited by the operator; re-enroll the id to "
            "manage it here)")


@external_agents_group.command("release")
@click.argument("agent_id")
def xa_release_cmd(agent_id: str) -> None:
    """Lift AGENT_ID's auto-containment and clear its denial window."""
    from .. import external_agents as xa
    from ..revocation import ProtectedRevocationError, shared

    try:
        released = shared().run_if_unprotected(
            f"agent:{agent_id}",
            lambda: xa.release(agent_id, released_by="cli"),
        )
    except ProtectedRevocationError as exc:
        raise click.ClickException(
            "agent is security-contained; use `maverick control-plane release`"
        ) from exc
    except Exception as exc:
        raise click.ClickException(
            "containment authority is unavailable; gateway release refused"
        ) from exc
    if not released:
        raise click.ClickException(f"agent {agent_id!r} is not enrolled")
    click.echo(click.style(f"released {agent_id!r}", fg="green")
               + " — containment lifted, denial window cleared")


@external_agents_group.command("reset-budget")
@click.argument("agent_id")
def xa_reset_budget_cmd(agent_id: str) -> None:
    """Zero AGENT_ID's active budget meter and clear the over-budget flag.

    The lifetime total is preserved — this changes what counts against the
    cap from now on, never what was historically reported."""
    from .. import external_agents as xa
    if not xa.reset_budget(agent_id, reset_by="cli"):
        raise click.ClickException(f"agent {agent_id!r} is not enrolled")
    click.echo(click.style(f"budget reset for {agent_id!r}", fg="green")
               + " — the meter starts from $0.00 now (monthly accounting)")


@external_agents_group.command("remove")
@click.argument("agent_id")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def xa_remove_cmd(agent_id: str, yes: bool) -> None:
    """Unenroll AGENT_ID: removes the trust entry + enrollment metadata.

    The fleet-memory roster keeps its history (provenance is never
    rewritten). Prefer `revoke` when you may want the agent back."""
    from .. import external_agents as xa
    if not yes:
        click.confirm(f"Unenroll {agent_id!r}? Its credentials stop working "
                      "and its ceilings/meters are deleted.", abort=True)
    from ..revocation import ProtectedRevocationError, shared

    # Removing a contained agent would let a fresh enroll come back live
    # without the security release, so removal waits for that release.
    action_errors: list[Exception] = []

    def _unenroll() -> bool:
        try:
            return xa.unenroll(agent_id)
        except Exception as exc:  # reported below, not as a containment failure
            action_errors.append(exc)
            return False

    try:
        removed = shared().run_if_unprotected(f"agent:{agent_id}", _unenroll)
    except ProtectedRevocationError as exc:
        raise click.ClickException(
            "agent is security-contained; use `maverick control-plane release`"
        ) from exc
    except Exception as exc:
        raise click.ClickException(
            "containment authority is unavailable; remove refused"
        ) from exc
    if action_errors:
        raise click.ClickException(
            f"could not remove {agent_id!r}: {action_errors[0]}") from action_errors[0]
    if removed:
        click.echo(click.style(f"removed {agent_id!r}", fg="yellow"))
    else:
        raise click.ClickException(f"agent {agent_id!r} is not enrolled")
