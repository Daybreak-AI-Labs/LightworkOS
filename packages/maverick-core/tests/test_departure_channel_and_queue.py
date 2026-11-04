"""Departure inventory and linked member retirement are not feature bypasses."""

from maverick import personal_identity as identity
from maverick.job_queue import JobQueue


def test_recorded_link_denies_inactive_member_even_when_sharing_disabled(monkeypatch):
    monkeypatch.setattr(identity, "enabled", lambda: False)
    monkeypatch.setattr(identity, "_read", lambda: {"links": [{"id": "one", "principal": "user:a", "channel": "slack", "user_id": "account-bound"}]})
    monkeypatch.setattr(identity, "principal_current", lambda principal: False)
    assert identity.channel_membership_current("slack", "account-bound") is False
    assert identity.channel_membership_current("slack", "different-account") is True
    assert len(identity.recorded_channels("user:a")) == 1
    assert identity.linked_channels("user:a") == []


def test_all_kinds_queue_inventory_is_bounded_by_initial_high_water(tmp_path):
    queue = JobQueue(db_path=tmp_path / "jobs.db")
    queue.enqueue("run_goal", {"owner": "user:a"})
    queue.enqueue("other_module", {"owner": "user:a"})
    iterator = queue.iter_pending(page_size=1)
    first = next(iterator)
    queue.enqueue("later", {"owner": "user:a"})
    assert {job.kind for job in [first, *iterator]} == {"run_goal", "other_module"}
    assert [job.kind for job in queue.iter_pending("other_module")] == ["other_module"]
