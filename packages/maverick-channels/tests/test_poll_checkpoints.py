"""Actual tenant checkpoint/inbox persistence with fake bounded source pages."""
from __future__ import annotations

import asyncio

import pytest
from maverick_channels import polling
from maverick_channels.polling import PollCheckpoint, PollPage


async def _initial():
    return {"watermark": "start"}


def test_page_bound_resume_and_complete_only_after_admission(monkeypatch):
    monkeypatch.setattr(polling, "MAX_PAGES", 2)
    admitted, seen = [], []
    async def fetch(state):
        index = int(state["cursor"] or "0")
        seen.append(index)
        return PollPage([{"id": index}], str(index + 1) if index < 4 else None,
                        completed={"watermark": "end"})
    async def admit(item, state):
        assert state["watermark"] == "start"
        admitted.append(item["id"])
        return True
    async def run():
        for index in range(3):
            checkpoint = PollCheckpoint("fixture", "account")
            row = await checkpoint.load(_initial)
            await checkpoint.drain(row, fetch, admit)
            saved = checkpoint.store.get(row["id"])
            assert saved["watermark"] == ("end" if index == 2 else "start")
    asyncio.run(run())
    assert seen == admitted == list(range(5))


@pytest.mark.parametrize("boundary", ["fetch", "admit"])
def test_failure_keeps_uncovered_cursor_and_restarts_page(boundary):
    fail, admitted = [True], []
    async def fetch(state):
        index = int(state["cursor"] or "0")
        if boundary == "fetch" and index == 1 and fail.pop():
            raise RuntimeError("429 fixture")
        return PollPage([{"id": index}], "1" if index == 0 else None, completed={"watermark": "end"})
    async def admit(item, state):
        if boundary == "admit" and item["id"] == 1 and fail.pop():
            raise OSError("crash fixture before receipt")
        admitted.append(item["id"])
        return True
    async def run():
        checkpoint = PollCheckpoint("fixture", "account")
        row = await checkpoint.load(_initial)
        with pytest.raises((RuntimeError, OSError)):
            await checkpoint.drain(row, fetch, admit)
        row = checkpoint.store.get(row["id"])
        assert row["cursor"] == "1" and row["watermark"] == "start" and row["status"] == "incomplete_error"
        fail.append(False)
        await checkpoint.drain(row, fetch, admit)
        assert checkpoint.store.get(row["id"])["watermark"] == "end"
    asyncio.run(run())
    assert admitted == [0, 1]


def test_cycle_is_visible_bounded_and_never_completes_range():
    calls = []
    async def fetch(state):
        calls.append(state["cursor"])
        return PollPage([], "same", completed={"watermark": "unsafe"})
    async def admit(item, state):
        return True
    async def run():
        checkpoint = PollCheckpoint("fixture", "account")
        row = await checkpoint.load(_initial)
        await checkpoint.drain(row, fetch, admit)
        row = checkpoint.store.get(row["id"])
        assert row["status"] == "incomplete_cursor_cycle" and row["watermark"] == "start"
    asyncio.run(run())
    assert calls == [None, "same"]


def test_deadline_does_not_wait_for_unbounded_provider(monkeypatch):
    monkeypatch.setattr(polling, "POLL_DEADLINE_SECONDS", 0.05)
    cancelled = []
    async def fetch(state):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)
    async def admit(item, state):
        pytest.fail("Unreturned page admitted")
    async def run():
        checkpoint = PollCheckpoint("fixture", "account")
        row = await checkpoint.load(_initial)
        with pytest.raises(asyncio.TimeoutError):
            await checkpoint.drain(row, fetch, admit)
        assert checkpoint.store.get(row["id"])["status"] == "incomplete_error"
    asyncio.run(run())
    assert cancelled == [True]
