"""Ops-maintenance CLI groups: cache, retention, encryption, local-runtime.

Registered by importing this module at the end of
the package __init__ so the @main.group decorators fire on package import.
"""
from __future__ import annotations

import click

from . import main


@main.command("preflight")
@click.option(
    "--profile",
    type=click.Choice(["run", "cockpit"]),
    default="run",
    show_default=True,
    help="Readiness contract to evaluate.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit stable machine-readable JSON.",
)
def operator_preflight_cmd(profile: str, as_json: bool) -> None:
    """Run a deterministic, offline install-readiness check.

    Unlike ``doctor``, preflight makes no network calls and creates no state.
    It exits non-zero when the selected profile has a blocker.
    """

    from ..operator_preflight import collect, render, render_json

    report = collect(profile=profile)
    click.echo(render_json(report) if as_json else render(report))
    if not report.ready:
        raise click.exceptions.Exit(1)


@main.group("cache")
def cache_group() -> None:
    """Inspect and clear in-process caches (file reads, repo map, embeddings)."""


@cache_group.command("stats")
def cache_stats_cmd() -> None:
    """Show cache sizes."""
    import json as _json

    from ..cache import stats
    click.echo(_json.dumps(stats(), default=str, indent=2))


@cache_group.command("purge")
@click.option(
    "--scope", "scopes", multiple=True,
    type=click.Choice(["files", "repo_map", "skill_embeddings", "all"]),
    help="Scope to purge (repeatable). Default: all.",
)
def cache_purge_cmd(scopes: tuple[str, ...]) -> None:
    """Purge cache(s)."""
    import json as _json

    from ..cache import purge
    report = purge(scopes or ("all",))
    click.echo(_json.dumps(report, default=str, indent=2))


# ----- Retention enforcement ------------------------------------------

@main.group("retention")
def retention_group() -> None:
    """Enforce ~/.maverick/config.toml [retention] rules."""


@retention_group.command("enforce")
@click.option("--dry-run", is_flag=True, help="Report what would be removed.")
@click.option("--audit-days", type=int, default=None,
              help="Override [retention].audit_days.")
@click.option("--episodes-days", type=int, default=None,
              help="Override [retention].episodes_days.")
@click.option("--events-days", type=int, default=None,
              help="Override [retention].events_days.")
@click.option("--messages-days", type=int, default=None,
              help="Override [retention].messages_days.")
@click.option("--usage-days", type=int, default=None,
              help="Override [retention].usage_days (cost-ledger buckets).")
def retention_enforce_cmd(
    dry_run: bool,
    audit_days: int | None,
    episodes_days: int | None,
    events_days: int | None,
    messages_days: int | None,
    usage_days: int | None,
) -> None:
    """Apply retention rules to the audit log and world model."""
    import json as _json

    from ..audit.retention import enforce
    # CLI overrides take precedence if any are set; otherwise read config.
    cfg: dict | None = None
    if any(
        v is not None
        for v in (audit_days, episodes_days, events_days, messages_days, usage_days)
    ):
        cfg = {}
        if audit_days is not None:
            cfg["audit_days"] = audit_days
        if episodes_days is not None:
            cfg["episodes_days"] = episodes_days
        if events_days is not None:
            cfg["events_days"] = events_days
        if messages_days is not None:
            cfg["messages_days"] = messages_days
        if usage_days is not None:
            cfg["usage_days"] = usage_days
    report = enforce(config=cfg, dry_run=dry_run)
    click.echo(_json.dumps(report, default=str, indent=2))


@main.group("encryption")
def encryption_group() -> None:
    """At-rest encryption maintenance (see docs/encryption.md)."""


@encryption_group.command("migrate")
@click.option("--dry-run", is_flag=True,
              help="Report what would be sealed without writing.")
@click.option("--backup/--no-backup", default=False,
              help="Opt in to a pre-migration plaintext backup next to a SQLite DB.")
@click.pass_context
def encryption_migrate_cmd(ctx, dry_run: bool, backup: bool) -> None:
    """Seal existing plaintext in the world DB (turns, facts, messages, questions).

    Enabling encryption only seals NEW writes; this seals data written before it
    was on. Idempotent and safe to re-run. Requires at-rest encryption enabled.

    The reseal is in place. By default no plaintext backup is written; pass
    --backup to write a timestamped plaintext snapshot alongside the DB first
    (mode 0600), and delete that backup once you have verified the migration.
    Postgres migrates the active tenant; --backup is SQLite-only.
    """
    from pathlib import Path

    from ..crypto_at_rest import EncryptionUnavailable
    from ..encryption_migrate import backup_world_db, migrate_postgres_world, migrate_world_db
    from ..world_model_backends.postgres import is_postgres_configured, open_postgres_world

    postgres = is_postgres_configured()
    db = Path(ctx.obj["db"])
    try:
        if postgres:
            if backup:
                raise click.ClickException("--backup is SQLite-only; take a Postgres database backup before migrating")
            with open_postgres_world() as world:
                report = migrate_postgres_world(world, dry_run=dry_run)
        elif not dry_run and backup and db.exists():
            # Only snapshot when there is plaintext left to seal, so idempotent
            # re-runs don't litter identical backups. The CLI owns the backup
            # (so it can echo the path); the real run below skips its own.
            if sum(migrate_world_db(db, dry_run=True).values()):
                bpath = backup_world_db(db)
                click.echo(f"backed up plaintext world DB to {bpath} "
                           "(mode 0600; delete once the migration is verified)")
        if not postgres:
            report = migrate_world_db(db, dry_run=dry_run, backup=False)
    except EncryptionUnavailable as e:
        raise click.ClickException(str(e)) from e
    verb = "would seal" if dry_run else "sealed"
    for key in sorted(report):
        click.echo(f"  {key}: {verb} {report[key]}")
    total = sum(report.values())
    click.echo(
        f"{verb} {total} value(s) total" + (" (dry run)" if dry_run else "")
    )
    # Once legacy rows are sealed, strict mode (treat an unsealed value in a
    # sealed column as tampering, instead of trusting it as plaintext) becomes
    # safe to turn on -- nudge the operator there, since nothing else does.
    if not dry_run:
        try:
            from ..crypto_at_rest import strict_at_rest
            from ..world_model import migrated_marker_path
            if postgres:
                click.echo("active Postgres tenant rebound; completion recorded in the database")
            elif migrated_marker_path(db).exists():
                click.echo("every sealed column is bound to its table, column and "
                           "tenant; unsealed values in sealed columns are now withheld "
                           "(strict) for this store")
            elif not strict_at_rest():
                click.echo(
                    "tip: now that legacy rows are sealed, set [encryption] "
                    "strict = true (or MAVERICK_ENCRYPT_STRICT=1) so an unsealed "
                    "value in a sealed column is treated as tampering."
                )
        except Exception:  # pragma: no cover - never fail the command on a tip
            pass


@encryption_group.command("backup-key")
@click.option("--to", "dest", required=True,
              type=click.Path(file_okay=False, dir_okay=True),
              help="Directory to copy the key material into (created 0700).")
def encryption_backup_key_cmd(dest: str) -> None:
    """Copy the at-rest key material to a directory for secure escrow.

    The key file is the ONLY way to read sealed data -- if it is lost, that data
    is unrecoverable. This copies the primary key and any rotation-keyring keys
    (each 0600) so you can store them in a secrets manager / offline vault. Keep
    the copies at least as protected as the originals; do not leave them next to
    the data they unlock.
    """
    from pathlib import Path

    from ..crypto_at_rest import EncryptionUnavailable, backup_key_material
    try:
        written = backup_key_material(Path(dest))
    except EncryptionUnavailable as e:
        raise click.ClickException(str(e)) from e
    for p in written:
        click.echo(f"  backed up {p}")
    click.echo(f"copied {len(written)} key file(s) to {dest} -- store them "
               "securely and delete any working copy you don't need.")


@encryption_group.command("rotate")
def encryption_rotate_cmd() -> None:
    """Rotate the process-wide at-rest encryption key (additive, no re-encrypt).

    Mints a new active key in the rotation keyring. New writes are sealed under
    it immediately; all prior keys are retained so existing data stays readable
    -- no flag-day re-encrypt, no data loss. Keep the previous key(s) available
    until you have re-sealed old data (e.g. `maverick encryption migrate`).
    Per-tenant envelope keys rotate via their own KMS, not this command.
    """
    from ..crypto_at_rest import EncryptionUnavailable, rotate_at_rest_key
    try:
        key_id = rotate_at_rest_key()
    except EncryptionUnavailable as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"rotated at-rest key; new active key-id = {key_id}")
    click.echo("new writes seal under it; prior keys retained for reads. Keep "
               "the old key material until old data is re-sealed.")


@main.group("local-runtime")
def local_runtime_group() -> None:
    """Plan the local model-server runtime (vLLM / TGI / llama.cpp)."""


@local_runtime_group.command("plan")
def local_runtime_plan() -> None:
    """Print the server command Lightwork WOULD run -- nothing is started.

    Composes the argv (and any env toggles) from [local_runtime] in
    ~/.maverick/config.toml plus MAVERICK_LOCAL_RUNTIME_* overrides.
    """
    import shlex

    from ..local_runtime import Launcher, LocalRuntimeError
    try:
        launcher = Launcher()
        argv, env = launcher.plan()
    except LocalRuntimeError as e:
        raise click.ClickException(str(e)) from e
    if not launcher.cfg["enabled"]:
        click.echo("# local runtime is DISABLED ([local_runtime] enabled = false); dry plan only")
    for key in sorted(env):
        click.echo(f"{key}={env[key]} \\")
    click.echo(shlex.join(argv))


@main.group("journal")
def journal_group() -> None:
    """Workspace mutation journal: list, diff, and revert an agent's file
    edits ([workspace] journal = true; off by default)."""


def _journal_goal_arg(goal: int | None):
    """CLI goal selector: an explicit --goal id, else the ad-hoc bucket."""
    return goal if goal is not None else "adhoc"


@journal_group.command("list")
@click.option("--goal", type=int, default=None,
              help="Goal id (default: the ad-hoc bucket).")
def journal_list_cmd(goal: int | None) -> None:
    """Show what the journal captured for a goal."""
    from ..workspace_journal import is_capped, list_entries
    gid = _journal_goal_arg(goal)
    entries = list_entries(gid)
    if not entries:
        click.echo("(no journal entries; is [workspace] journal enabled?)")
        return
    for e in entries:
        state = "existed" if e.get("existed") else "created"
        skipped = e.get("skipped_reason")
        suffix = f"  [pre-image {skipped}]" if skipped else ""
        click.echo(f"{e.get('seq', 0):6d}  {state:7s}  {e.get('path')}{suffix}")
    if is_capped(gid):
        click.echo("NOTE: journal hit its cap; later writes were NOT captured "
                   "(full revert will refuse; use --partial).")
    click.echo("Shell-driven mutations (rm/mv/redirects) are not journaled; "
               "see the audit trail for those commands.")


@journal_group.command("diff")
@click.option("--goal", type=int, default=None,
              help="Goal id (default: the ad-hoc bucket).")
def journal_diff_cmd(goal: int | None) -> None:
    """Unified diff: each journaled file's pre-run state vs the disk now."""
    from ..workspace_journal import diff_goal
    click.echo(diff_goal(_journal_goal_arg(goal)))


@journal_group.command("revert")
@click.option("--goal", type=int, default=None,
              help="Goal id (default: the ad-hoc bucket).")
@click.option("--partial", is_flag=True,
              help="Restore what was captured even if the journal is "
                   "incomplete (cap hit / oversized pre-images).")
@click.option("--dry-run", is_flag=True, help="Report only; touch nothing.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def journal_revert_cmd(goal: int | None, partial: bool, dry_run: bool,
                       yes: bool) -> None:
    """Restore every journaled file to its pre-run bytes (newest-first).

    Writes one signed `workspace_revert` audit row and archives the journal
    directory so the revert cannot be replayed by accident.
    """
    from ..workspace_journal import revert_goal
    gid = _journal_goal_arg(goal)
    if not (dry_run or yes):
        click.confirm(
            f"Revert journaled file mutations for {gid!r}? This rewrites "
            "workspace files to their pre-run bytes", abort=True)
    try:
        res = revert_goal(gid, partial=partial, dry_run=dry_run)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    verb = "would revert" if dry_run else "reverted"
    click.echo(f"{verb} {res['reverted']} file(s), deleted {res['deleted']} "
               f"created file(s), skipped {res['skipped']} "
               f"({res['entries']} journal entries; "
               f"{'complete' if res['complete'] else 'PARTIAL'})")
    if res.get("archived"):
        click.echo(f"journal archived at {res['archived']}")
