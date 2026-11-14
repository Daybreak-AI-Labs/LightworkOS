"""Knowledge-plane CLI: seed curated corpora, inspect collections, and prove a
subject's documents were erased.

Registered via import at the end of the cli package so the decorators fire on
import. Disabled knowledge remains optional. Configured but unavailable
knowledge is reported as an error, never a successful verification or erasure.
"""
from __future__ import annotations

import json as _json

import click

from . import main


@main.group("knowledge")
def knowledge() -> None:
    """Knowledge base: seed corpora, inspect collections, verify erasure."""


@knowledge.command("reindex")
@click.argument("collection")
@click.option("--tenant", default=None, help="Tenant data plane (default: active).")
def knowledge_reindex(collection: str, tenant: str | None) -> None:
    """Explicitly migrate a collection to the configured embedding model.

    SQLite and pgvector replace vectors atomically, preserving source content.
    Other stores require ingesting originals into a new collection, validating
    it, then switching sources. Provider embedding calls may incur costs.
    """
    from ..knowledge_admin import open_knowledge_base
    kb = None
    try:
        kb = open_knowledge_base(tenant=tenant, require_existing=True)
        if kb is None:
            raise click.ClickException("knowledge is disabled")
        count = kb.reindex(collection)
        click.echo(f"reindexed {count} chunk(s) in {collection}")
    except (RuntimeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        if kb is not None:
            kb.close()


@knowledge.command("collections")
@click.option("--tenant", default=None, help="Tenant data plane (default: active).")
def knowledge_collections(tenant: str | None) -> None:
    """List knowledge collections and their chunk counts."""
    from ..knowledge_admin import open_knowledge_base
    kb = open_knowledge_base(tenant=tenant)
    if kb is None:
        click.echo("knowledge RAG is disabled or maverick-knowledge is not installed.")
        return
    try:
        cols = kb.collections()
        if not cols:
            click.echo("no knowledge collections yet.")
            return
        for c in cols:
            n = kb.store.count(c) if hasattr(kb.store, "count") else "?"
            click.echo(f"  {c}: {n} chunk(s)")
    finally:
        kb.close()


@knowledge.command("residual")
@click.option("--channel", required=True, help="Channel name (e.g. slack, sms).")
@click.option("--user", required=True, help="The channel user_id to check.")
@click.option("--tenant", default=None, help="Tenant data plane (default: active).")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def knowledge_residual(channel: str, user: str, tenant: str | None,
                       as_json: bool) -> None:
    """Count a subject's residual document chunks across all collections.

    Zero after `maverick erase` — the knowledge half of the right-to-erasure
    proof (`maverick erase-verify` already folds this count into its verdict).
    """
    from ..knowledge_admin import KnowledgeUnavailable, count_subject
    try:
        n = count_subject(channel, user, tenant=tenant)
    except KnowledgeUnavailable as exc:
        if as_json:
            click.echo(_json.dumps({"channel": channel, "user": user,
                                    "knowledge_chunks": None, "clean": False,
                                    "checked": False, "error": str(exc)}))
            raise SystemExit(2) from exc
        raise click.ClickException(str(exc)) from exc
    if as_json:
        click.echo(_json.dumps({"channel": channel, "user": user,
                                "knowledge_chunks": n, "clean": n == 0}))
    else:
        verdict = "CLEAN" if n == 0 else f"{n} residual chunk(s)"
        click.echo(f"knowledge residual for {channel}:{user}: {verdict}")
    if n:
        raise SystemExit(1)


@knowledge.command("erase-subject")
@click.option("--channel", required=True, help="Channel name.")
@click.option("--user", required=True, help="The channel user_id to erase.")
@click.option("--tenant", default=None, help="Tenant data plane (default: active).")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def knowledge_erase_subject(channel: str, user: str, tenant: str | None,
                            yes: bool) -> None:
    """Erase one subject's ingested document chunks from the knowledge base.

    `maverick erase` already does this as part of a full Art. 17 erasure; this
    is the knowledge-only entry point for targeted cleanup.
    """
    if not yes:
        click.confirm(
            f"Erase all knowledge chunks for {channel}:{user}?", abort=True)
    from ..knowledge_admin import KnowledgeUnavailable, erase_subject
    try:
        removed = erase_subject(channel, user, tenant=tenant)
    except KnowledgeUnavailable as exc:
        raise click.ClickException(str(exc)) from exc
    total = sum(removed.values())
    click.echo(f"erased {total} knowledge chunk(s) for {channel}:{user}")
    if removed:
        click.echo("  per collection: "
                   + ", ".join(f"{c}={n}" for c, n in sorted(removed.items())))


@knowledge.command("seed")
@click.option("--collection", default=None,
              help="Only seed this collection (default: all shipped corpora).")
@click.option("--tenant", default=None, help="Tenant data plane (default: active).")
@click.option("--list", "list_only", is_flag=True,
              help="List the shipped starter corpora and exit.")
def knowledge_seed(collection: str | None, tenant: str | None,
                   list_only: bool) -> None:
    """Ingest the shipped curated regulatory corpora into their collections.

    Public-domain regulatory summaries (GDPR, EU AI Act, NIST AI RMF, CCPA)
    grounded with article citations, so a privacy/GRC specialist can cite the
    regulation out of the box. Idempotent per document (content-hashed).
    Runs keyless — the deterministic embedder needs no provider.
    """
    from ..knowledge_seed import available_corpora, seed_corpora
    corpora = available_corpora()
    if list_only:
        for c in corpora:
            click.echo(f"  {c['collection']}: {c['title']} ({c['documents']} docs)")
        return
    if collection is not None and collection not in {c["collection"] for c in corpora}:
        raise click.BadParameter(
            "unknown collection; use knowledge seed --list to see available corpora",
            param_hint="--collection",
        )
    from ..knowledge_admin import open_knowledge_base
    kb = open_knowledge_base(tenant=tenant)
    if kb is None:
        click.echo(
            "knowledge RAG is disabled. Enable it (installer wizard or "
            "[knowledge] enable = true) and install maverick-knowledge first.",
            err=True)
        raise SystemExit(1)
    try:
        report = seed_corpora(kb, only=collection)
    finally:
        kb.close()
    total = sum(report.values())
    for col, n in sorted(report.items()):
        click.echo(f"  {col}: ingested {n} chunk(s)")
    click.echo(f"seeded {total} chunk(s) across {len(report)} collection(s).")
