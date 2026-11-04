"""Operator controls for bounded channel journal maintenance."""
from __future__ import annotations

import click


@click.group("channel-maintenance")
def channel_maintenance():
    """Maintain durable channel receipts in the selected workspace."""


@channel_maintenance.command("compact")
@click.option("--limit", type=click.IntRange(1, 100), default=100, show_default=True)
def compact(limit):
    """Visit one persisted retention window; repeat to cover a large journal."""
    from .delivery import DeliveryJournal

    count = DeliveryJournal().compact_delivered(limit=limit)
    click.echo(f"Compacted {count} delivered receipts; visited up to {limit} identities.")
    click.echo("The next call continues the persisted scan. Zero compacted does not prove a complete scan.")
    click.echo("Deduplication identities remain until their retention window ends; tidying may not free a slot yet.")
    click.echo("At capacity, review Settings > All settings > Chat channels to raise the saved-message limit.")
