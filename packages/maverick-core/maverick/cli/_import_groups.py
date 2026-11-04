"""``maverick import`` -- pull clients' existing automations into Lightwork.

Registered by importing this module at the end of the package __init__ so the
``@main.group`` decorator fires on package import (same pattern as the other
``_*_groups`` modules).
"""
from __future__ import annotations

import json as _json

import click

from . import main


@main.group("import")
def import_group() -> None:
    """Import automations from other platforms (n8n/Make/Workato/...).

    Two modes by platform: definition import (fetch + translate the real
    workflow) for platforms that expose it, and connect-and-trigger for the
    rest. Gated by [automation_import] enable / MAVERICK_AUTOMATION_IMPORT.
    """


@import_group.command("sources")
def import_sources_cmd() -> None:
    """List the automation platforms Lightwork can import from."""
    from ..automation_import import available_sources, get_importer
    rows = []
    for s in available_sources():
        imp = get_importer(s)
        mode = "definition-import" if imp.can_fetch_definitions else "connect-and-trigger"
        rows.append({"source": s, "mode": mode})
    click.echo(_json.dumps(rows, indent=2))


def _load_raws(from_file: str | None, source: str) -> list[dict]:
    """Definitions from a JSON file (a single object or a list), else a live
    fetch via the importer's credentialed API."""
    from ..automation_import import get_importer
    if from_file:
        from pathlib import Path
        try:
            text = Path(from_file).read_text(encoding="utf-8")
        except OSError as e:
            raise click.ClickException(f"cannot read {from_file}: {e}") from e
        try:
            data = _json.loads(text)
        except ValueError as e:
            raise click.ClickException(f"{from_file} is not valid JSON: {e}") from e
        if isinstance(data, dict):
            # Accept either a bare definition or an API envelope {"data": [...]}.
            return data.get("data", [data]) if "data" in data else [data]
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        raise click.ClickException("--from-file must contain a JSON object or array")
    return get_importer(source).fetch()


@import_group.command("run")
@click.argument("source")
@click.option("--from-file", "from_file", default=None,
              help="Import from an exported definitions JSON file instead of a live fetch.")
@click.option("--dry-run", is_flag=True, help="Translate + preview only; write nothing.")
@click.option("--activate-schedules", is_flag=True,
              help="Auto-create Lightwork schedules for recovered cron triggers.")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.pass_context
def import_run_cmd(ctx, source, from_file, dry_run, activate_schedules, as_json) -> None:
    """Import automations from SOURCE (e.g. ``n8n``) into Lightwork templates."""
    from ..automation_import import ImporterError, enabled, get_importer, materialize, translate_all
    if not enabled():
        raise click.ClickException(
            "automation import is off; enable [automation_import] in config.toml "
            "or set MAVERICK_AUTOMATION_IMPORT=1"
        )
    try:  # validate the source up-front so --from-file with a bad source is a
        get_importer(source)  # clean error, not an uncaught ImporterError later
        raws = _load_raws(from_file, source)
    except ImporterError as e:
        raise click.ClickException(str(e)) from e

    automations = translate_all(source, raws)
    if not automations:
        raise click.ClickException(f"no importable automations found from {source!r}")

    queue = None
    if activate_schedules and not dry_run:
        from ..job_queue import JobQueue
        queue = JobQueue()  # default queue DB path

    results = []
    for a in automations:
        res = materialize(a, save=not dry_run, queue=queue)
        results.append({
            "source": a.source, "name": a.name, "template": res.template_name,
            "created": res.created_template, "trigger": a.trigger.kind,
            "suggested_trigger": res.suggested_trigger, "schedule": res.schedule,
            "tools": res.tool_hints, "notes": res.notes,
        })

    if as_json:
        click.echo(_json.dumps(results, default=str, indent=2))
        return
    verb = "Would import" if dry_run else "Imported"
    click.echo(f"{verb} {len(results)} automation(s) from {source}:")
    for r in results:
        click.echo(f"  • {r['name']}  →  template '{r['template']}' (trigger: {r['trigger']})")
        if r["schedule"]:
            click.echo(f"      schedule created: cron {r['schedule']['cron']}")
        elif r["suggested_trigger"]:
            click.echo(f"      next: wire {r['suggested_trigger']['kind']} trigger")
        for note in r["notes"]:
            click.echo(f"      note: {note}")
    if dry_run:
        click.echo("(dry run — nothing written)")
