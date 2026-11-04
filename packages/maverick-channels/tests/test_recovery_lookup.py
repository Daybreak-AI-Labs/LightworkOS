"""Source checkpoint lookup never admits, delivers or changes channel work."""
import json
import sqlite3

import pytest
from maverick_channels import imessage
from maverick_channels import recovery_lookup as lookup


def test_imessage_dates_and_identity_without_private_content_or_writes(tmp_path, monkeypatch):
    path = tmp_path / "chat.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE message(date INTEGER, guid TEXT, text TEXT)")
        conn.executemany("INSERT INTO message VALUES(?,?,?)", [(800000000000000000 + i * 1000000000, "guid-" + str(i), "private secret") for i in range(53)])
    original = path.read_bytes()
    monkeypatch.setattr(imessage, "CHAT_DB", path)
    monkeypatch.setattr(imessage.platform, "system", lambda: "Darwin")
    channel = lookup.configured("imessage", {"enabled": True, "allowed_user_ids": ["allowed"]})
    page = lookup.lookup(channel, minimum="1", before=None)
    assert len(page["candidates"]) == 50 and page["next_before"] == "4"
    assert "private secret" not in json.dumps(page) and "guid-" not in json.dumps(page)
    assert page["candidates"][0]["source_at"].endswith("+00:00")
    older = lookup.lookup(channel, minimum="1", before=page["next_before"])
    assert [row["position"] for row in older["candidates"]] == ["3", "2", "1"]
    assert path.read_bytes() == original


def test_disabled_source_cannot_be_substituted():
    with pytest.raises(ValueError, match="disabled"):
        lookup.configured("imessage", {"enabled": False})


def test_mastodon_uses_only_bounded_read_and_keeps_ids_exact(monkeypatch):
    import httpx
    client_type = httpx.AsyncClient
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=[{"id": "99999999999999999999", "created_at": "2026-09-30T12:00:00Z", "status": {"content": "private body"}}])
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client_type(transport=httpx.MockTransport(handler), **kwargs))
    channel = lookup.configured("mastodon", {"enabled": True, "instance": "source.invalid", "access_token": "synthetic", "allowed_user_ids": ["allowed"]})
    page = lookup.lookup(channel, minimum="1", before=None)
    assert page["candidates"][0]["position"] == "99999999999999999999"
    assert "private body" not in json.dumps(page)
    assert len(requests) == 1 and requests[0].method == "GET"


def test_mastodon_outage_never_yields_checkpoint(monkeypatch):
    import httpx
    client_type = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client_type(transport=httpx.MockTransport(lambda request: httpx.Response(503)), **kwargs))
    channel = lookup.configured("mastodon", {"enabled": True, "instance": "source.invalid", "access_token": "synthetic", "allowed_user_ids": ["allowed"]})
    with pytest.raises(httpx.HTTPStatusError):
        lookup.lookup(channel, minimum="1", before=None)


def test_the_local_message_database_handle_is_closed_after_a_lookup(tmp_path, monkeypatch):
    path = tmp_path / "chat.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE message(date INTEGER, guid TEXT, text TEXT)")
        conn.execute("INSERT INTO message VALUES(800000000000000000, 'guid-1', 'private')")
    monkeypatch.setattr(imessage, "CHAT_DB", path)
    monkeypatch.setattr(imessage.platform, "system", lambda: "Darwin")
    opened = []
    real = sqlite3.connect

    class Tracked:
        def __init__(self, connection):
            self._connection = connection
            opened.append(self)
            self.closed = False

        def __getattr__(self, name):
            return getattr(self._connection, name)

        def __enter__(self):
            return self._connection.__enter__()

        def __exit__(self, *exc):
            return self._connection.__exit__(*exc)

        def close(self):
            self.closed = True
            self._connection.close()

    monkeypatch.setattr(lookup.sqlite3, "connect", lambda *a, **k: Tracked(real(*a, **k)))
    channel = lookup.configured("imessage", {"enabled": True, "allowed_user_ids": ["allowed"]})
    lookup.lookup(channel, minimum="1", before=None)
    assert opened and all(handle.closed for handle in opened)
