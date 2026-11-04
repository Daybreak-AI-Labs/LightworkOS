"""iMessage send-safety smoke test.

Critical security property: send() must pass user-controlled text as
argv to AppleScript, never interpolate it into the script body. An LLM
emitting `"; tell application "Finder" to ...` must be inert.

We can only run the macOS-only import path on macOS, but we *can* test
the AppleScript constant + the subprocess.run shape on any platform.
"""
from __future__ import annotations

import gc
import platform
import sqlite3
from unittest.mock import patch

import pytest


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="iMessage channel imports macOS-only APIs at construction",
)
def test_send_passes_text_via_argv_not_interpolation():
    """The send() path must invoke osascript with text/handle as argv."""
    from maverick_channels.imessage import iMessageChannel

    async def _noop(_):
        return ""

    # Construct without hitting chat.db. We patch the file-existence check.
    with patch("maverick_channels.imessage.CHAT_DB") as fake_db:
        fake_db.exists.return_value = True
        fake_db.__fspath__ = lambda: "/tmp/fake_chat.db"
        chan = iMessageChannel(
            handler=_noop, poll_interval=1, allowed_user_ids={"+1555"},
        )

    import asyncio
    with patch("maverick_channels.imessage.subprocess.run") as run_mock:
        run_mock.return_value.returncode = 0
        asyncio.run(chan.send(
            "+1555",
            'malicious"; tell app "Finder" to delete every file',
        ))

    assert run_mock.called
    args, kwargs = run_mock.call_args
    # The cmdline must be osascript reading from stdin, with text + handle as argv.
    argv = args[0]
    assert argv[0] == "osascript"
    assert argv[1] == "-"
    assert argv[2] == 'malicious"; tell app "Finder" to delete every file'
    assert argv[3] == "+1555"
    # And the script body comes from stdin, not the cmdline.
    assert "input" in kwargs
    assert "on run argv" in kwargs["input"]


def test_send_script_does_not_interpolate_text():
    """Static check on the script constant itself."""
    from maverick_channels.imessage import _SEND_SCRIPT
    # The script reads argv -- it must not contain `%s` or `{` placeholders
    # that suggest python-side string formatting.
    assert "%s" not in _SEND_SCRIPT
    assert "{" not in _SEND_SCRIPT
    assert "on run argv" in _SEND_SCRIPT
    assert "item 1 of argv" in _SEND_SCRIPT
    assert "item 2 of argv" in _SEND_SCRIPT


def _make_channel():
    """Build an iMessageChannel without hitting the macOS-only __init__ guards."""
    from maverick_channels.imessage import iMessageChannel

    chan = iMessageChannel.__new__(iMessageChannel)
    chan.allowed_user_ids = {"+1555"}
    chan.poll_interval = 0
    chan._last_rowid = 0
    chan._stop = False
    return chan


def test_start_survives_send_failure():
    """A transient send() failure (e.g. osascript TimeoutExpired / OSError)
    must NOT propagate out of start() and kill the poll loop.

    An unguarded `await self.send(...)` would let a subprocess.TimeoutExpired
    (which check=False does not suppress) terminate the whole receive loop
    permanently.
    """
    import asyncio
    import subprocess

    chan = _make_channel()

    fetched = {"done": False}

    def _fetch_new():
        if fetched["done"]:
            chan._stop = True
            return []
        fetched["done"] = True
        return [("+1555", "hi", 1, "GUID-1")]

    sent = {"attempts": 0}

    async def _dispatch(_msg):
        return "reply"

    async def _send(_user, _text):
        sent["attempts"] += 1
        raise subprocess.TimeoutExpired(cmd="osascript", timeout=10)

    chan._fetch_new = _fetch_new
    chan._latest_rowid = lambda: 0
    chan.handler = _dispatch
    chan.send = _send

    # The send failure is logged and the loop continues to a clean stop
    # instead of raising TimeoutExpired out of start().
    asyncio.run(asyncio.wait_for(chan.start(), timeout=5))

    assert sent["attempts"] == 1  # the send was attempted (and failed) once


def test_start_skips_empty_reply():
    """An empty reply (action-only goal) should not trigger a send call."""
    import asyncio

    chan = _make_channel()

    fetched = {"done": False}

    def _fetch_new():
        if fetched["done"]:
            chan._stop = True
            return []
        fetched["done"] = True
        return [("+1555", "hi", 1, "GUID-1")]

    async def _dispatch(_msg):
        return ""

    sent = {"attempts": 0}

    async def _send(_user, _text):
        sent["attempts"] += 1

    chan._fetch_new = _fetch_new
    chan._latest_rowid = lambda: 0
    chan.handler = _dispatch
    chan.send = _send

    asyncio.run(asyncio.wait_for(chan.start(), timeout=5))

    assert sent["attempts"] == 0


def test_chat_database_reads_close_their_connections(tmp_path, monkeypatch):
    """Each read of chat.db closes its connection when the call returns.

    A `with sqlite3.connect(...)` block only commits; the connection stays open
    until a cyclic GC pass (CPython 3.12), so GC is disabled for this test.
    """
    from maverick_channels import imessage

    db = tmp_path / "chat.db"
    setup = sqlite3.connect(db)
    setup.executescript(
        "CREATE TABLE message (ROWID INTEGER, text TEXT, guid TEXT, is_from_me INTEGER,"
        " handle_id INTEGER);"
        "CREATE TABLE handle (ROWID INTEGER, id TEXT);"
        "INSERT INTO handle VALUES (1, '+1555');"
        "INSERT INTO message VALUES (1, 'hi', 'guid-1', 0, 1);"
    )
    setup.commit()
    setup.close()
    monkeypatch.setattr(imessage, "CHAT_DB", db)
    opened = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(imessage.sqlite3, "connect", recording_connect)
    chan = _make_channel()
    gc.disable()
    try:
        assert chan._latest_rowid() == 1
        assert chan._fetch_new() == [("+1555", "hi", 1, "guid-1")]
    finally:
        gc.enable()
    assert len(opened) == 2
    for connection in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
