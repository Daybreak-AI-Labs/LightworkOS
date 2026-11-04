"""``maverick cortex`` -- the company brain from the command line.

Registered by importing this module at the end
of the package __init__ so the @main.group decorators fire on package import.
The kernel surface is :mod:`maverick.cortex`; this module only renders it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from ..cortex import SOURCES
from . import _strip_terminal_control, main, open_world


@main.group("cortex")
def cortex_group() -> None:
    """Cortex, the company brain: one governed memory over every source.

    Knowledge (cited documents), skills, self-harness lessons, the Operating
    Record and fleet memory answer one query under one provenance envelope,
    and every read and write lands as one audit row (who asked, which
    sources answered, which were denied and why). Tenant-exact by
    construction. Switched off as a whole by ``[cortex] enable = false`` or
    ``MAVERICK_CORTEX=0``.
    """


# ---- status ------------------------------------------------------------------

def _n(count: int, noun: str, plural: str | None = None) -> str:
    return f"{count} {noun if count == 1 else (plural or noun + 's')}"


def _row_knowledge(info: dict[str, Any]) -> tuple[str, str]:
    if not info.get("available"):
        return "unavailable", info.get("error") or "[knowledge] enable = false or no store"
    cols = [str(c) for c in info.get("collections") or []]
    return _n(len(cols), "collection"), ", ".join(cols) or "-"


def _row_skills(info: dict[str, Any]) -> tuple[str, str]:
    detail = info.get("error") or f"{int(info.get('verified') or 0)} verified"
    return _n(int(info.get("count") or 0), "skill"), detail


def _row_lessons(info: dict[str, Any]) -> tuple[str, str]:
    detail = info.get("error") or _n(int(info.get("models") or 0), "model")
    if not info.get("error") and not info.get("enabled", True):
        detail += "; self-harness off"
    return _n(int(info.get("lines") or 0), "line"), detail


def _row_record(info: dict[str, Any]) -> tuple[str, str]:
    detail = info.get("error") or (
        f"{_n(int(info.get('n_goals') or 0), 'goal')}, "
        f"{_n(int(info.get('n_approvals') or 0), 'approval')}, "
        f"{_n(int(info.get('n_human_decisions') or 0), 'human decision')}")
    return _n(int(info.get("entries") or 0), "entry", "entries"), detail


def _row_fleet(info: dict[str, Any]) -> tuple[str, str]:
    if not info.get("enabled"):
        return "off", info.get("error") or "[fleet_memory] enable = false"
    ingested = (info.get("ingested") or {}).values()
    ok = sum(int(c.get("success") or 0) for c in ingested)
    bad = sum(int(c.get("failure") or 0) for c in ingested)
    return _n(len(info.get("agents") or []), "agent"), f"{ok} success / {bad} failure"


_ROWS = {"knowledge": _row_knowledge, "skills": _row_skills, "lessons": _row_lessons,
         "record": _row_record, "fleet": _row_fleet}


def _clean(text: Any) -> str:
    """Strip terminal control bytes from untrusted text, line by line (the
    stripper removes every C0 byte, newlines included)."""
    return "\n".join(_strip_terminal_control(line) for line in str(text).splitlines())


def _on(value: Any) -> str:
    return "on" if value else "off"


def _yes(value: Any) -> str:
    return "yes" if value else "no"


@cortex_group.command("status")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def cortex_status_cmd(ctx, as_json: bool) -> None:
    """What each source holds for the active tenant, plus the posture an
    auditor asks about: encryption at rest and tenant isolation."""
    import json as _json

    from .. import cortex
    st = cortex.status(world=open_world(ctx.obj["db"]))
    if as_json:
        click.echo(_json.dumps(st, indent=2, default=str))
        return
    if not st.get("enabled", True):
        click.echo(click.style(
            "cortex is disabled ([cortex] enable = false or MAVERICK_CORTEX=0); "
            "recall and deposit are refused", fg="yellow"))
    click.echo(f"tenant: {st.get('tenant') or '(none)'}")
    click.echo(f"  {'source':<10} {'holds':<18} detail")
    sources = st.get("sources") or {}
    for source in SOURCES:
        count, detail = _ROWS[source](sources.get(source) or {})
        click.echo(f"  {source:<10} {count:<18} {_clean(detail)}")
    enc = st.get("encryption") or {}
    iso = st.get("isolation") or {}
    click.echo(f"encryption  at rest: {_on(enc.get('at_rest'))}, "
               f"per tenant: {_on(enc.get('per_tenant'))}")
    click.echo(f"isolation   tenant floored: {_yes(iso.get('tenant_floored'))}, "
               f"pooled across tenants: {_yes(iso.get('pooled_across_tenants'))}")
    if iso.get("note"):
        click.echo(f"            {iso['note']}")


# ---- recall ------------------------------------------------------------------

def _render_hits(res: Any) -> None:
    n = len(res.hits)
    audited = "audited" if res.audited else click.style("NOT audited", fg="red")
    click.echo(f"cortex recall: {res.query!r}  tenant={res.tenant or '(none)'}  "
               f"{_n(n, 'hit')} in {res.took_ms}ms  {audited}")
    if not res.hits:
        click.echo("  no hits")
    for source in res.sources:
        group = [h for h in res.hits if h.source == source]
        if not group:
            continue
        click.echo(click.style(f"\n{source} ({len(group)})", bold=True))
        for i, h in enumerate(group, 1):
            click.echo(f"  [{i}] {_clean(h.citation)}  ({h.kind}, score={h.score:.2f})")
            for line in _clean(h.text).strip().splitlines():
                click.echo(f"      {line}")
    if res.denied:
        click.echo(click.style("\ndenied", bold=True))
        for source, why in res.denied.items():
            click.echo(f"  {source}: {_clean(why)}")


@cortex_group.command("recall")
@click.argument("query")
@click.option("--source", "sources", multiple=True, type=click.Choice(SOURCES),
              help="Consult only these sources (repeatable; default: all).")
@click.option("--domain", default=None,
              help="Department/domain scope for lessons, the record and fleet memory.")
@click.option("--model", "model_id", default=None,
              help="Recall the exact self-harness guidance block this model would be "
                   "given instead of a lexical match over the learned lines.")
@click.option("--k", default=5, show_default=True, help="Hits per source.")
@click.option("--json", "as_json", is_flag=True, help="Emit the result envelope as JSON.")
@click.option("--context", "as_context", is_flag=True,
              help="Print the prompt block an agent would receive (each hit with "
                   "its citation) instead of the grouped listing.")
@click.pass_context
def cortex_recall_cmd(ctx, query: str, sources: tuple[str, ...], domain: str | None,
                      model_id: str | None, k: int, as_json: bool,
                      as_context: bool) -> None:
    """Recall QUERY from every source under one envelope; audited once.

    Hits are grouped by source, each with its citation. Governed knowledge
    retrieval requires the authenticated Lightwork app. A source that is off
    or broken is listed under ``denied`` with its reason; the others still
    answer. The whole surface being off is an error, not an empty result.
    """
    import json as _json

    from .. import cortex
    wanted = tuple(sources) or SOURCES
    world = open_world(ctx.obj["db"]) if "record" in wanted else None
    res = cortex.recall(query, sources=wanted, domain=domain, model_id=model_id,
                        k=k, world=world)
    if "cortex" in res.denied:
        raise click.ClickException(res.denied["cortex"])
    if as_json:
        click.echo(_json.dumps(res.to_dict(), indent=2, default=str))
        return
    if as_context:
        click.echo(_clean(res.context()))
        return
    _render_hits(res)


# ---- deposit -----------------------------------------------------------------

@cortex_group.command("deposit")
@click.argument("text", required=False, default=None)
@click.option("--kind", type=click.Choice(["knowledge", "fleet"]), default="knowledge",
              show_default=True,
              help="knowledge: a cited chunk in the tenant's knowledge base; "
                   "fleet: a lesson through fleet memory's roster and Shield gates.")
@click.option("--collection", default="cortex", show_default=True,
              help="Knowledge collection to ingest into.")
@click.option("--source", default="",
              help="Provenance recorded on the chunk (default: the --file path, "
                   "else the caller).")
@click.option("--domain", default=None, help="Department/domain the deposit belongs to.")
@click.option("--file", "path", default=None,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="Read the text from PATH instead of the TEXT argument.")
def cortex_deposit_cmd(text: str | None, kind: str, collection: str, source: str,
                       domain: str | None, path: Path | None) -> None:
    """Deposit TEXT (or --file PATH) into Cortex. One audit row either way."""
    from .. import cortex
    if text is not None and path is not None:
        raise click.UsageError("give TEXT or --file PATH, not both")
    if path is not None:
        text = path.read_text(encoding="utf-8")
        source = source or str(path)
    if text is None or not text.strip():
        raise click.UsageError("nothing to deposit: give TEXT or --file PATH")
    ok, reason = cortex.deposit(text, kind=kind, collection=collection,
                                source=source, domain=domain)
    if not ok:
        raise click.ClickException(reason)
    click.echo(click.style(f"deposited into {kind}", fg="green") + f" -- {reason}")
