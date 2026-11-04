"""Sealed-attachment downloads share one bounded memory budget."""
from __future__ import annotations

import threading
import time

import pytest
from maverick_dashboard.decrypt_budget import ByteBudget, DecryptBusy


def test_reservations_wait_for_room_and_release_it():
    budget = ByteBudget(100)
    order = []
    with budget.reserve(80):
        def second():
            with budget.reserve(40, timeout=5):
                order.append("second")
        t = threading.Thread(target=second)
        t.start()
        time.sleep(0.1)
        assert order == []           # waiting: 80 + 40 > 100
        order.append("first-done")
    t.join(5)
    assert order == ["first-done", "second"]
    assert budget.in_use == 0


def test_a_request_that_cannot_get_room_in_time_is_told_plainly():
    budget = ByteBudget(100)
    with budget.reserve(100):
        with pytest.raises(DecryptBusy):
            with budget.reserve(1, timeout=0.05):
                pass
    assert budget.in_use == 0


def test_a_single_file_larger_than_the_budget_still_runs_alone():
    budget = ByteBudget(100)
    with budget.reserve(10_000):
        assert budget.in_use == 100
    assert budget.in_use == 0
