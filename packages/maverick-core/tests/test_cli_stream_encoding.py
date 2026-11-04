from __future__ import annotations

import io
import sys

import click
from maverick.cli import _configure_cli_text_streams


def test_cli_replaces_unencodable_glyphs_on_legacy_windows_stream(
    monkeypatch,
):
    """A frozen cp1252 console must not abort `maverick voice status`."""
    raw = io.BytesIO()
    stream = io.TextIOWrapper(
        raw,
        encoding="cp1252",
        errors="strict",
    )
    monkeypatch.setattr(sys, "stdout", stream)

    _configure_cli_text_streams()
    click.echo("✓ pywhispercpp engine (installed)")
    stream.flush()

    assert stream.errors == "replace"
    assert raw.getvalue().rstrip(b"\r\n") == (
        b"? pywhispercpp engine (installed)"
    )
