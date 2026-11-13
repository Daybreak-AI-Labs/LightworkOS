"""``maverick code`` -- a company's code in Lightwork: vaulted, improved by swarms,
merged only with a human's approval. The kernel surface is :mod:`maverick.codebase`."""
from __future__ import annotations

import json
from pathlib import Path

import click

from . import _strip_terminal_control, main, open_world


def _guard():
    from ..codebase import vault
    if not vault.enabled():
        raise click.ClickException("the code vault is off; set [codebase] enable = true")
    return vault


def _fail(exc: Exception):
    raise click.ClickException(str(exc)) from exc


@main.group("code")
def code_group() -> None:
    """Software development: protected repositories and governed feature swarms."""


@code_group.command("add")
@click.argument("name")
@click.argument("source")
@click.option("--branch", default=None, help="Default branch (else the source's HEAD).")
@click.option("--test", "test_command", default=None, help="Command that runs the test suite.")
@click.option("--protect", type=click.Choice(["block", "approve", "audit"]), default=None,
              help="Information-flow mode for every run over this code "
                   "(default: [codebase] default_protect).")
@click.option("--token-env", default=None,
              help="Environment variable holding the remote credential (never stored).")
def code_add(name, source, branch, test_command, protect, token_env) -> None:
    """Import SOURCE (a git URL or local path) into the vault as NAME."""
    vault = _guard()
    from ..config import get_codebase
    try:
        repo = vault.register(name, source, default_branch=branch, test_command=test_command,
                              protect=protect or get_codebase()["default_protect"],
                              token_env=token_env)
    except vault.VaultError as exc:
        _fail(exc)
    click.echo(f"vaulted {repo.name} ({repo.default_branch} @ {repo.head[:12]}, "
               f"protect={repo.protect})")


@code_group.command("list")
def code_list() -> None:
    """Registered repositories."""
    vault = _guard()
    for r in vault.list_repos():
        click.echo(f"  {r.name:24} {r.default_branch:12} {r.head[:12]}  protect={r.protect}  "
                   f"tests={'yes' if r.test_command else 'no'}")


@code_group.command("sync")
@click.argument("name")
def code_sync(name) -> None:
    """Fetch new upstream commits into the vault."""
    vault = _guard()
    try:
        report = vault.sync(name)  # per-branch outcome lists, not a Repo
        repo = vault.get(name)
    except vault.VaultError as exc:
        _fail(exc)
    updated = len(report.get("fast_forwarded", [])) + len(report.get("merged", []))
    kept = len(report.get("kept_ahead", [])) + len(report.get("diverged_kept", []))
    click.echo(f"{repo.name} now at {repo.head[:12]} ({updated} updated, "
               f"{len(report.get('added', []))} new, {kept} kept)")


@code_group.command("feature")
@click.argument("name")
@click.argument("title")
@click.option("--description", "-d", default="", help="What to build or change.")
@click.option("--max-dollars", default=None, type=float)
@click.option("--no-review", is_flag=True, help="Skip the independent diff review.")
def code_feature(name, title, description, max_dollars, no_review) -> None:
    """Have a swarm build TITLE in NAME; the change waits for approval."""
    vault = _guard()
    from ..codebase import features
    from . import _require_llm_key
    _require_llm_key()
    world = open_world()
    try:
        p = features.propose(world, name, title, description,
                             features.default_runner(max_dollars=max_dollars),
                             reviewer=None if no_review else features.default_reviewer())
    except vault.VaultError as exc:
        _fail(exc)
    finally:
        world.close()
    if p["status"] == "empty":
        click.echo(f"proposal {p['id']}: the swarm made no change")
        return
    tests = p["tests"]
    click.echo(f"proposal {p['id']} on {p['branch']}: {len(p['files'])} file(s); tests "
               + ("not configured" if tests is None else
                  "passed" if tests["passed"] else "FAILED")
               + f"; awaiting approval #{p['approval_id']}")


@code_group.command("proposals")
@click.argument("name", required=False)
def code_proposals(name) -> None:
    """Change proposals and their approval state."""
    _guard()
    from ..codebase import features
    world = open_world()
    try:
        for p in features.list_proposals(name):
            click.echo(f"  {p['id']}  {p['repo']:16} {features.status(world, p):9} "
                       f"{_strip_terminal_control(p['title'])[:60]}")
    finally:
        world.close()


@code_group.command("show")
@click.argument("pid")
def code_show(pid) -> None:
    """A proposal's diff, tests and review."""
    vault = _guard()
    from ..codebase import features
    try:
        p = features.find(pid)
    except vault.VaultError as exc:
        _fail(exc)
    click.echo(json.dumps({k: v for k, v in p.items() if k not in ("diff", "tests_output")},
                          indent=2, default=str))
    if p["tests_output"]:
        click.echo("\n--- tests ---\n" + _strip_terminal_control(p["tests_output"]))
    click.echo("\n--- diff ---\n" + _strip_terminal_control(p["diff"]))


@code_group.command("merge")
@click.argument("pid", required=False)
@click.option("--approved", "settle", is_flag=True,
              help="Merge every proposal approved since the last merge.")
def code_merge(pid, settle) -> None:
    """Merge an approved proposal into the vault's default branch."""
    vault = _guard()
    from ..codebase import features
    if bool(pid) == bool(settle):
        raise click.UsageError("give a proposal id or --approved")
    world = open_world()
    try:
        if settle:
            for r in features.settle(world):
                click.echo(f"  {r['id']} ({r['repo']}): {r['outcome']}")
        else:
            p = features.merge(world, pid)
            click.echo(f"merged {pid} into {p['repo']}")
    except vault.VaultError as exc:
        _fail(exc)
    finally:
        world.close()


@code_group.command("renew")
@click.argument("pid")
def code_renew(pid) -> None:
    """Park a fresh approval for a proposal whose approval expired unanswered
    (after 7 days) or could not be parked."""
    vault = _guard()
    from ..codebase import features
    world = open_world()
    try:
        aid = features.request_approval(world, features.find(pid))
    except (vault.VaultError, ValueError) as exc:  # ValueError: the card could not be built
        _fail(exc)
    finally:
        world.close()
    click.echo(f"approve codebase_merge #{aid} in the dashboard's approvals queue")


@code_group.command("push")
@click.argument("pid")
def code_push(pid) -> None:
    """Push an approved proposal's branch to the repository's source remote."""
    vault = _guard()
    from ..codebase import features
    world = open_world()
    try:
        branch = features.push(world, pid)
    except vault.VaultError as exc:
        _fail(exc)
    finally:
        world.close()
    click.echo(f"pushed {branch}; open the pull request on your host")


@code_group.command("export")
@click.argument("name")
@click.argument("dest", type=click.Path(file_okay=False))
def code_export(name, dest) -> None:
    """Write a plaintext clone to DEST (outside the vault's protection)."""
    vault = _guard()
    try:
        out = vault.export(name, Path(dest))
    except vault.VaultError as exc:
        _fail(exc)
    click.echo(f"exported {name} to {out}")
