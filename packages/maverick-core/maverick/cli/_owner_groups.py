"""``maverick owner`` -- this computer's owner account, run from the computer itself."""
from __future__ import annotations

import sys

import click

from ..work_discovery_identity import local_os_principal
from . import main


@main.group("owner")
def owner() -> None:
    """Manage this computer's owner account. Run these on the computer itself."""


@owner.command("reset-authenticator")
def owner_reset_authenticator() -> None:
    """Turn the owner's authenticator app off after a lost phone.

    For when the phone is lost and every recovery code is used, so no code can
    be given. You will be asked to type the owner's email to confirm. The app
    and its recovery codes are removed, and the owner must set the app up again.
    """
    try:
        from maverick_dashboard import local_owner_second_factor as second
    except ImportError:
        click.echo("The dashboard package is not installed on this computer, so the owner account "
                   "cannot be reset here.", err=True)
        sys.exit(2)
    from fastapi import HTTPException

    email = click.prompt("Type the owner's email to confirm")
    try:
        was_on = second.reset_by_operator(confirm_email=email, actor=local_os_principal())
    except HTTPException as exc:
        click.echo(f"ERROR: {exc.detail}", err=True)
        sys.exit(2)
    except (LookupError, ValueError) as exc:
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(2)
    if was_on:
        click.echo("The owner's authenticator app is off. Its recovery codes and any sign-in step in progress "
                   "were removed.")
    else:
        click.echo("No authenticator app was on. Any sign-in step in progress was removed.")
    click.echo('The owner must set up the authenticator app again. With [auth.local_owner] totp = "required", '
               "the owner's next passphrase sign-in forces that set-up before anything else.")
    click.echo("Until the owner sets it up again, the passphrase alone opens company sign-in and single sign-on "
               "changes and their recovery, as it does for any owner without the app.")
    if second.mode() == "off":
        click.echo('The setting [auth.local_owner] totp is "off", so the app cannot be set up again until it changes.')
