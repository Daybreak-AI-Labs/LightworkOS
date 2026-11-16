"""``maverick import`` -- pull clients' existing automations into Lightwork.

Registered by importing this module at the end of the package __init__ so the
``@main.group`` decorator fires on package import (same pattern as the other
``_*_groups`` modules).
"""
from __future__ import annotations

import json as _json
import logging
from collections import Counter

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
            if "data" not in data:
                return [data]
            data = data["data"]
            if not isinstance(data, list):
                raise click.ClickException("--from-file data must contain a JSON array")
        if isinstance(data, list):
            definitions = [d for d in data if isinstance(d, dict)]
            omitted = len(data) - len(definitions)
            if omitted:
                logging.getLogger(__name__).warning(
                    "Skipped %d import record(s) that are not JSON objects", omitted,
                )
            return definitions
        raise click.ClickException("--from-file must contain a JSON object or array")
    return get_importer(source).fetch()


def _active_cron_jobs(queue, *, marked: bool = False) -> dict[tuple[str, str], tuple[int, str]]:
    """``(title, cron) -> (job id, goal text)`` for cron goal jobs.

    A job that carries ``imported_from`` is an import's own schedule;
    ``materialize`` finds and updates it, so it is listed only when ``marked``
    is set (for a workflow that cannot be told apart by its mark).
    """
    active: dict[tuple[str, str], tuple[int, str]] = {}
    for job in queue.iter_pending("start_goal", include_running=True):
        payload = job.payload if isinstance(job.payload, dict) else {}
        cron = payload.get("__cron__")
        if cron and (marked or not payload.get("imported_from")):
            active.setdefault((str(payload.get("title") or ""), str(cron)),
                              (job.id, str(payload.get("text") or "")))
    return active


_SHARED_NAME = ("another workflow in this import has the same name and id, so their "
                "schedules cannot be told apart later; an import creates this schedule "
                "once and never changes it")


def _reuse_or_replace(queue, active, automation) -> tuple[int | None, str | None]:
    """Decide what to do with an unmarked schedule that looks like ``automation``.

    Returns ``(job id to keep, note)``. Schedules made before imports marked
    their jobs cannot be told apart from a dashboard or ``schedule`` job with
    the same title and cron, so a matching job is kept rather than duplicated
    and one whose text differs is never changed here: it is left, and the
    note says so.
    """
    title, body = automation.render()
    found = active.get((title[:200], automation.trigger.cron or ""))
    if found is None:
        return None, None
    job_id, text = found
    if text == body:
        return job_id, f"schedule already active (job {job_id}); not duplicated"
    return job_id, (f"schedule job {job_id} has the same title and cron but different "
                    "text; it was left unchanged and no new schedule was created -- "
                    "cancel that job and re-run the import to replace it")


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

    skipped: list[tuple[str, str]] = []
    automations = translate_all(source, raws, skipped)
    for name, reason in skipped:
        click.echo(f"Not imported: {name} ({reason})", err=True)
    if not automations:
        raise click.ClickException(f"no importable automations found from {source!r}")

    queue = None
    active: dict[tuple[str, str], tuple[int, str]] = {}
    every: dict[tuple[str, str], tuple[int, str]] = {}
    if activate_schedules and not dry_run:
        from ..job_queue import JobQueue
        queue = JobQueue()  # default queue DB path
        active = _active_cron_jobs(queue)
        every = _active_cron_jobs(queue, marked=True)
    # Two workflows that share a mark would each rewrite the other's
    # schedule, and a workflow with no id shares its mark with any other of
    # the same name, in this import or a later one. They are scheduled unmarked.
    marks = Counter(a.import_ref() for a in automations)

    results = []
    for a in automations:
        # materialize updates the schedule an earlier import marked as its
        # own. An unmarked look-alike is kept, never duplicated or rewritten;
        # so is any look-alike of a workflow that shares its mark.
        shared = marks[a.import_ref()] > 1
        unmarked = shared or not a.source_id
        existing, note = (_reuse_or_replace(queue, every if unmarked else active, a)
                          if queue is not None else (None, None))
        res = materialize(a, save=not dry_run, mark_schedule=not unmarked,
                          queue=None if existing is not None else queue)
        if shared and a.source_id and queue is not None:
            res.notes.append(_SHARED_NAME)
        if existing is not None:
            res.suggested_trigger = None
            res.notes = [n for n in res.notes if not n.startswith("schedule recovered;")]
        if note:
            res.notes.append(note)
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
            verb = "updated" if r["schedule"].get("updated") else "created"
            click.echo(f"      schedule {verb}: cron {r['schedule']['cron']}")
        elif r["suggested_trigger"]:
            click.echo(f"      next: wire {r['suggested_trigger']['kind']} trigger")
        for note in r["notes"]:
            click.echo(f"      note: {note}")
    if dry_run:
        click.echo("(dry run — nothing written)")
