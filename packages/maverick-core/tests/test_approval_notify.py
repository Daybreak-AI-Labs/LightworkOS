"""Announcing a new approval runs under the tenant of the request."""
from __future__ import annotations

import contextvars
import threading

from maverick import approval_notify, world_model

TENANT = contextvars.ContextVar("test_tenant", default="default")


def test_the_announcement_world_is_opened_under_the_callers_context_and_closed(monkeypatch):
    seen = {}
    done = threading.Event()

    class World:
        closed = False

        def close(self):
            World.closed = True

    def open_world(*args, **kwargs):
        seen["opened_for"] = TENANT.get()
        return World()

    def announce(world, approval_id):
        seen["announced_for"] = TENANT.get()
        seen["world"] = world
        done.set()

    monkeypatch.setattr(world_model, "open_world", open_world)
    monkeypatch.setattr(approval_notify, "install_announcers", lambda: None)
    monkeypatch.setattr(approval_notify, "announcements_configured", lambda: True)
    import maverick.channel_approvals as approvals
    monkeypatch.setattr(approvals, "announce_new_approval", announce)
    TENANT.set("acme")
    approval_notify.approval_created(7)
    assert done.wait(5)
    for thread in threading.enumerate():
        if thread.name == "approval-announce-7":
            thread.join(5)
    assert seen["opened_for"] == "acme" and seen["announced_for"] == "acme"
    assert World.closed is True


def test_a_world_the_caller_supplied_is_not_closed_here(monkeypatch):
    done = threading.Event()

    class World:
        closed = False

        def close(self):
            World.closed = True

    monkeypatch.setattr(approval_notify, "install_announcers", lambda: None)
    monkeypatch.setattr(approval_notify, "announcements_configured", lambda: True)
    import maverick.channel_approvals as approvals
    monkeypatch.setattr(approvals, "announce_new_approval", lambda world, approval_id: done.set())
    approval_notify.approval_created(8, world=World())
    assert done.wait(5)
    for thread in threading.enumerate():
        if thread.name == "approval-announce-8":
            thread.join(5)
    assert World.closed is False
