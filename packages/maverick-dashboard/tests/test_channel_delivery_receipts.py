"""Read-only administrator visibility without source text or secret disclosure."""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from maverick import world_model
from maverick_channels.base import IncomingMessage
from maverick_channels.delivery import DeliveryJournal
from maverick_dashboard import api
from starlette.requests import Request


def _request():
    return Request({"type": "http", "method": "GET", "path": "/api/v1/channels/delivery-receipts", "headers": []})


def test_receipt_window_and_detail_exclude_message_and_reply_content(monkeypatch, tmp_path):
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    gates = []
    monkeypatch.setattr(api, "require_global_permission", lambda request, permission: gates.append(permission))
    journal = DeliveryJournal()
    row = journal.admit(IncomingMessage(user_id="private-person", text="confidential source", channel="email"),
                         external_id="secret-source-id", account="private-account")
    row = journal.change(row, execution="completed", delivery="delivery_unknown", reply={"text": "confidential reply"},
                         chunks={"email-0": {"state": "delivery_unknown", "provider_id": "provider-receipt",
                                              "idempotency_key": "stable-provider-key"}})
    page = asyncio.run(api.channel_delivery_receipts(_request(), limit=1))
    assert gates == ["admin"] and page["next_cursor"] and page["bounded_window"]
    assert page["receipts"][0]["delivery"] == "delivery_unknown"
    detail = asyncio.run(api.channel_delivery_receipts(_request(), receipt_id=row["id"]))
    assert detail["receipts"][0]["chunks"][0]["provider_id"] == "provider-receipt"
    for secret in ("private-person", "confidential source", "confidential reply", "secret-source-id", "private-account"):
        assert secret not in str(page) and secret not in str(detail)


def test_receipt_visibility_requires_global_admin_before_store_access(monkeypatch):
    def deny(*args):
        raise HTTPException(status_code=403, detail="admin required")
    monkeypatch.setattr(api, "require_global_permission", deny)
    monkeypatch.setattr(DeliveryJournal, "__init__", lambda *args: pytest.fail("Receipt read before authorization"))
    with pytest.raises(HTTPException) as error:
        asyncio.run(api.channel_delivery_receipts(_request()))
    assert error.value.status_code == 403


def test_intake_capacity_is_admin_only_and_excludes_message_content(monkeypatch, tmp_path):
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(api, "require_global_permission", lambda *args: None)
    DeliveryJournal().admit(IncomingMessage(user_id="private-person", text="private-message", channel="email"),
                            external_id="private-id", account="private-account")
    status = asyncio.run(api.channel_intake_capacity(_request()))
    assert status["used"] == 1 and status["count_exact"] and status["limit"] >= 1
    assert "private" not in str(status)

    def deny(*args):
        raise HTTPException(status_code=403, detail="admin required")

    monkeypatch.setattr(api, "require_global_permission", deny)
    monkeypatch.setattr(DeliveryJournal, "__init__", lambda *args: pytest.fail("Capacity read before authorization"))
    with pytest.raises(HTTPException) as error:
        asyncio.run(api.channel_intake_capacity(_request()))
    assert error.value.status_code == 403


def test_poll_checkpoint_visibility_excludes_provider_cursor_and_history_floor(monkeypatch):
    from maverick_channels.polling import PollCheckpoint

    monkeypatch.setattr(api, "require_global_permission", lambda *args: None)
    async def prepare():
        checkpoint = PollCheckpoint("threads", "private-account")
        async def initialize():
            return {"floor": "private-history-floor"}
        row = await checkpoint.load(initialize)
        await checkpoint.change(row, cursor="private-provider-token", status="incomplete_page_bound")
    asyncio.run(prepare())
    result = asyncio.run(api.channel_poll_checkpoints(_request(), limit=1))
    assert result["bounded_window"] and result["checkpoints"][0]["has_continuation"]
    assert result["checkpoints"][0]["status"] == "incomplete_page_bound"
    for private in ("private-account", "private-history-floor", "private-provider-token"):
        assert private not in str(result)


def test_poll_checkpoint_visibility_checks_admin_before_store(monkeypatch):
    from maverick.governed_records import GovernedRecordStore

    def deny(*args):
        raise HTTPException(status_code=403, detail="admin required")
    monkeypatch.setattr(api, "require_global_permission", deny)
    monkeypatch.setattr(GovernedRecordStore, "__init__", lambda *args: pytest.fail("Store read before authorization"))
    with pytest.raises(HTTPException) as error:
        asyncio.run(api.channel_poll_checkpoints(_request()))
    assert error.value.status_code == 403


def test_receipt_window_lists_an_unreadable_receipt_and_the_message_waiting_behind_it(monkeypatch, tmp_path):
    # A receipt that cannot be read (its key is unavailable) made the whole
    # status window fail. It is listed as unreadable, and the newer message of
    # its conversation shows what it waits behind.
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(api, "require_global_permission", lambda *args: None)
    journal = DeliveryJournal()
    older = journal.admit(IncomingMessage(user_id="private-person", text="older", channel="signal"),
                          external_id="older-id", account="private-account")
    newer = journal.admit(IncomingMessage(user_id="private-person", text="newer", channel="signal"),
                          external_id="newer-id", account="private-account")
    hold = {"id": older["id"], "created_at": older["created_at"], "unreadable_since": 1000.0}
    journal.change(newer, held_behind=hold)
    readable_get = DeliveryJournal.get

    def get(self, record_id):
        if record_id == older["id"]:
            raise ValueError("sealed receipt does not open")
        return readable_get(self, record_id)

    monkeypatch.setattr(DeliveryJournal, "get", get)
    page = asyncio.run(api.channel_delivery_receipts(_request(), limit=10))
    by_id = {item["id"]: item for item in page["receipts"]}
    assert by_id[older["id"]] == {"id": older["id"], "readable": False}
    assert by_id[newer["id"]]["readable"] is True and by_id[newer["id"]]["held_behind"] == hold
    detail = asyncio.run(api.channel_delivery_receipts(_request(), receipt_id=older["id"]))
    assert detail["receipts"] == [{"id": older["id"], "readable": False}]
    for secret in ("private-person", "older-id", "newer-id", "private-account"):
        assert secret not in str(page) and secret not in str(detail)
