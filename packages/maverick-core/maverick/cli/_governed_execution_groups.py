"""CLI for the governed-execution planes: session kernel, self-refinement,
run forking.

Everything the modules do, as verbs — so an operator can drive and inspect
them on a headless install, and so a human can exercise the kernel without an
agent turn. Registered by importing this module
at the end of the package __init__ so the @main.group decorators fire on
package import.
"""
from __future__ import annotations

import click

from . import main


def _when(ts) -> str:
    if not ts:
        return "-"
    import datetime
    return datetime.datetime.fromtimestamp(
        float(ts), datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# -- session kernel -----------------------------------------------------------

@main.group("repl")
def repl_group() -> None:
    """Run Python in the governed session kernel.

    Statements execute through the sandbox behind a PREPARE/COMMIT receipt —
    no receipt, no execution — and only JSON-serializable globals survive to
    the next statement. OFF by default: set ``[repl] enable`` (or
    MAVERICK_REPL=1) to admit code execution.
    """


@repl_group.command("exec")
@click.argument("code")
@click.option("--session", default="", help="Reuse an existing session id.")
@click.option("--goal", type=int, default=None,
              help="Bind receipts and the step trail to this goal.")
def repl_exec_cmd(code: str, session: str, goal: int | None) -> None:
    """Execute CODE and print its output."""
    from .. import governed_repl
    if not governed_repl.enabled():
        raise click.ClickException(
            "the session kernel is disabled; set [repl] enable = true")
    try:
        session_id = session or governed_repl.open_session(goal)
        result = governed_repl.execute(session_id, code, goal_id=goal)
    except governed_repl.ReplError as e:
        raise click.ClickException(str(e)) from e
    if result.get("stdout"):
        click.echo(result["stdout"].rstrip())
    if result.get("stderr"):
        click.echo(result["stderr"].rstrip(), err=True)
    if result.get("dropped"):
        click.echo("not carried forward (not JSON-serializable): "
                   + ", ".join(sorted(result["dropped"])), err=True)
    click.echo(f"session {session_id} · {result.get('statement_sha256', '')[:12]}"
               f" · exit {result.get('exit_code')}", err=True)
    if not result.get("ok"):
        raise SystemExit(1)


@repl_group.command("transcript")
@click.argument("session_id")
def repl_transcript_cmd(session_id: str) -> None:
    """Print the append-only statement ledger for SESSION_ID."""
    from .. import governed_repl
    try:
        rows = governed_repl.transcript(session_id)
    except governed_repl.ReplError as e:
        raise click.ClickException(str(e)) from e
    if not rows:
        click.echo("no statements recorded")
        return
    for n, row in enumerate(rows, 1):
        ok = "ok" if row.get("ok") else f"exit {row.get('exit_code')}"
        click.echo(f"{n:>3}. {_when(row.get('at'))} · "
                   f"{str(row.get('statement_sha256') or '')[:12]} · {ok}")
        excerpt = str(row.get("excerpt") or "").strip()
        if excerpt:
            click.echo(f"     {excerpt.splitlines()[0][:100]}")


@repl_group.command("close")
@click.argument("session_id")
def repl_close_cmd(session_id: str) -> None:
    """Close SESSION_ID and drop its carried namespace."""
    from .. import governed_repl
    click.echo("closed" if governed_repl.close_session(session_id)
               else "already closed")


# -- self-refinement ----------------------------------------------------------

@main.group("refine")
def refine_group() -> None:
    """Propose, approve, apply, and revert changes to the agent's own
    prompts, skills, and memory.

    A proposal never self-applies: with ``[harness_refine] require_approval``
    (the default) it parks a dual-control approval bound to the change's
    digest, and applying snapshots first so a revert is always real.
    """


@refine_group.command("propose")
@click.option("--failure", required=True,
              help="What went wrong that motivates the change.")
@click.option("--target", type=click.Choice(["prompt", "skill", "memory"]),
              default="prompt", show_default=True)
@click.option("--name", default="", help="Which prompt/skill/memory entry.")
@click.option("--change", required=True, help="The proposed new text.")
@click.option("--rationale", default="", help="Why this should help.")
@click.option("--by", "proposed_by", default="cli",
              help="Who is proposing (recorded on the approval).")
def refine_propose_cmd(failure: str, target: str, name: str, change: str,
                       rationale: str, proposed_by: str) -> None:
    """Park a refinement proposal for a human decision."""
    from .. import harness_refine
    try:
        out = harness_refine.propose(
            {"failure": failure, "target": target, "name": name,
             "change": change, "rationale": rationale},
            proposed_by=proposed_by)
    except harness_refine.RefineError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"proposal {out.get('id')} · {out.get('status')}")
    if out.get("approval_id"):
        click.echo(f"awaiting approval #{out['approval_id']} "
                   "(decide it in the dashboard queue)")


@refine_group.command("list")
@click.option("--status", default="", help="Filter: pending/applied/reverted.")
def refine_list_cmd(status: str) -> None:
    """List refinement proposals, newest first."""
    from .. import harness_refine
    rows = harness_refine.list_proposals(status=status or None)
    if not rows:
        click.echo("no proposals")
        return
    for row in rows:
        click.echo(f"{row.get('id')}  {row.get('status'):<9} "
                   f"{row.get('target'):<7} {row.get('name') or '-':<20} "
                   f"{_when(row.get('proposed_at'))}")


@refine_group.command("apply")
@click.argument("proposal_id")
@click.option("--approval-id", type=int, default=None,
              help="The approved approval authorizing this apply.")
def refine_apply_cmd(proposal_id: str, approval_id: int | None) -> None:
    """Apply an approved proposal (snapshots first, so revert is real)."""
    from .. import harness_refine
    try:
        out = harness_refine.apply(proposal_id, applied_by="cli",
                                   approval_id=approval_id)
    except harness_refine.RefineError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"applied {proposal_id} · snapshot {out.get('snapshot') or '-'}")


@refine_group.command("revert")
@click.argument("proposal_id")
@click.option("--by", "reverted_by", default="cli")
def refine_revert_cmd(proposal_id: str, reverted_by: str) -> None:
    """Restore the snapshot taken when PROPOSAL_ID was applied."""
    from .. import harness_refine
    click.echo("reverted" if harness_refine.revert(
        proposal_id, reverted_by=reverted_by) else "nothing to revert")


@refine_group.command("show")
def refine_show_cmd() -> None:
    """Show the refinements currently in force (what the agent is told)."""
    from .. import harness_refine
    rows = harness_refine.refinements()
    if not rows:
        click.echo("no refinements in force")
        return
    for row in rows:
        click.echo(f"[{row.get('target')}] {row.get('name') or '-'}")
        click.echo(f"  {str(row.get('change') or '').strip()[:200]}")


# -- run forking --------------------------------------------------------------

@main.group("run-tree")
def run_tree_group() -> None:
    """Fork runs and inspect the run tree.

    A fork copies the parent's event trail up to a chosen point onto a new
    goal, so the Operating Record can hold a counterfactual beside what
    actually happened. Nothing is re-executed — these are record rows.
    """


@run_tree_group.command("fork")
@click.argument("goal_id", type=int)
@click.option("--at-event", type=int, default=None,
              help="Event id to fork at (default: the whole trail).")
@click.option("--label", default="", help="Why this branch exists.")
@click.option("--by", "forked_by", default="cli")
def runs_fork_cmd(goal_id: int, at_event: int | None, label: str,
                  forked_by: str) -> None:
    """Fork GOAL_ID into a new run."""
    from .. import session_tree
    try:
        child = session_tree.fork(goal_id, at_event=at_event, label=label,
                                  forked_by=forked_by)
    except session_tree.SessionTreeError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"forked goal {goal_id} -> {child}")


@run_tree_group.command("show")
@click.argument("goal_id", type=int)
def runs_tree_cmd(goal_id: int) -> None:
    """Print the fork tree rooted at GOAL_ID."""
    from .. import session_tree
    try:
        root = session_tree.tree(goal_id)
    except session_tree.SessionTreeError as e:
        raise click.ClickException(str(e)) from e

    def _emit(node: dict, depth: int = 0) -> None:
        label = f" [{node['label']}]" if node.get("label") else ""
        click.echo(f"{'  ' * depth}{node.get('goal_id')}  "
                   f"{node.get('status', '?'):<8} "
                   f"{str(node.get('title') or '')[:60]}{label}")
        for child in node.get("children") or []:
            _emit(child, depth + 1)

    _emit(root)


@run_tree_group.command("list")
@click.option("--limit", type=int, default=20, show_default=True)
def runs_forked_cmd(limit: int) -> None:
    """List runs that have forks, newest first."""
    from .. import session_tree
    rows = session_tree.roots(limit=limit)
    if not rows:
        click.echo("no forked runs")
        return
    for row in rows:
        click.echo(f"{row.get('goal_id'):>6}  {row.get('forks')} fork(s)  "
                   f"{_when(row.get('last_forked_at'))}  "
                   f"{str(row.get('title') or '')[:60]}")
