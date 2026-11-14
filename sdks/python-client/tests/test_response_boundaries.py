"""Regression checks for the checkout-only client's response boundary."""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lightwork_client import Lightwork, LightworkError  # noqa: E402


def test_transport_failure_traceback_does_not_reveal_bearer():
    token = "synthetic-" + "credential-value"
    calls = []

    def failing(method, url, headers, body, timeout):
        calls.append(method)
        raise OSError(headers["Authorization"])

    with pytest.raises(LightworkError) as caught:
        Lightwork("https://dashboard.example", token, transport=failing).submit_goal("Once")
    assert token not in "".join(traceback.format_exception(caught.value))
    assert "[redacted]" in str(caught.value)
    assert caught.value.status is None
    assert calls == ["POST"]


@pytest.mark.parametrize("method,arguments,status,body", [
    ("health", (), 200, None),
    ("submit_goal", ("Once",), 201, []),
    ("goal_receipt", ("receipt-key",), 200, "accepted"),
    ("get_goal", (1,), 200, []),
    ("list_goals", (), 200, {}),
    ("list_goals", (), 200, [1]),
    ("goal_events", (1,), 200, False),
    ("list_approvals", (), 200, None),
    ("spend", (), 200, 10),
])
def test_success_json_requires_the_documented_container(method, arguments, status, body):
    calls = []

    def response(*args):
        calls.append(args[0])
        return status, {}, json.dumps(body).encode()

    client = Lightwork("https://dashboard.example", transport=response)
    with pytest.raises(LightworkError) as caught:
        getattr(client, method)(*arguments)
    assert caught.value.status == status
    assert len(calls) == 1
