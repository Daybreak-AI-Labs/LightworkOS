"""Explicit offline maintenance of the existing A2A durable claim authority."""
from __future__ import annotations

import json

import click

from . import main


@main.group("a2a")
def a2a() -> None:
    """Inspect and maintain A2A task authority."""


@a2a.command("migrate-claims")
@click.option("--tenant", required=True, help="Exactly one existing source tenant.")
def migrate_claims(tenant: str) -> None:
    """Import private SQLite claims into configured Postgres while stopped.

    Preserves unknown outcomes and consumed identities. Retains the original
    ledger as a private archive and emits a content-bound completion receipt.
    This explicit maintenance command never runs during ordinary startup.
    """
    from .. import control_plane_lease
    from ..a2a_migration import migrate_local_tasks
    from ..governed_records import GovernedRecordBackendError

    try:
        receipt = migrate_local_tasks(tenant)
    except (ValueError, GovernedRecordBackendError, control_plane_lease.ControlPlaneBusy,
            control_plane_lease.LeaseUnavailable) as error:
        raise click.ClickException(str(error)) from None
    # failure-policy: fail_closed
    except Exception as error:
        # Driver/provider exceptions can contain credentials. Preserve details
        # in the bound failure type, not unredacted connection diagnostics.
        raise click.ClickException(
            f"A2A migration did not complete ({type(error).__name__}); preserve "
            "the source, binding and shared checkpoint, resolve the authority "
            "failure, then rerun the same tenant migration."
        ) from None
    click.echo(json.dumps(receipt, sort_keys=True))
