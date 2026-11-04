# lightwork-client

A small Python client for the Lightwork dashboard REST API (`/api/v1`). It uses
only the standard library (`urllib`, `json`, `ssl`, `ipaddress`), so it has no
dependencies and runs on Python 3.11 to 3.12.

**Not published.** This package is a checkout-only helper. It is not on PyPI,
it is not a member of the uv workspace, and it is not part of the release
cohort. Its version (`0.1.0`) is not tied to the Lightwork packages.

The REST contract itself is documented in [`docs/api.md`](../../docs/api.md).
The live spec is at `/openapi.json` on your dashboard.

## Install from a checkout

From the repository root, in a virtual environment:

```sh
python -m venv .venv
. .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install ./sdks/python-client
```

To work on the client itself, use `pip install -e ./sdks/python-client`.
You can also copy the `lightwork_client/` folder next to your script and import
it without installing.

## Authenticate

Pass a personal or service-account API key (`lwk_...`, from **Account › API
keys**) or the dashboard's `MAVERICK_DASHBOARD_TOKEN`. Either one is sent as
`Authorization: Bearer`.

```python
import os
from lightwork_client import Lightwork

lw = Lightwork("https://lightwork.example.com", os.environ["LIGHTWORK_API_KEY"])
```

Without a token, a local dashboard on loopback accepts writes only from its own
origin. The client always sends `Origin: <base URL origin>` on `POST`, so that
check passes:

```python
lw = Lightwork("http://127.0.0.1:8765")   # no token, same computer only
```

A bearer token over plain `http://` to a non-loopback host is refused. Use
`https://` for remote dashboards. A base URL that contains a username or
password is refused too, and the error does not repeat it: pass the key as
`token` only.

## Quick start: submit a goal and follow it

Create the idempotency key yourself and store it before you send the request.
Send the goal with `submit_once()` below. It recovers an uncertain start with
the same key and never sends the work again under a new key. The test suite runs
a copy of this function with identical logic (`test_a_lost_claim_is_recovered_by_replaying_the_same_key`),
so the documented path is exercised against the real app.

```python
import time
import uuid

from lightwork_client import Lightwork, LightworkError


def submit_once(lw, key, title, description="", **limits):
    """Submit under one key. Recover an uncertain start; never use a new key."""
    for _attempt in range(3):
        try:
            return lw.submit_goal(title, description, idempotency_key=key, **limits)
        except LightworkError as exc:
            if exc.status is not None and exc.status < 500 and exc.status != 409:
                raise  # a refusal such as 400, 403 or 422: fix the request, do not retry
        # No response, a 5xx, or a 409 ("retained; reconcile before retrying").
        try:
            receipt = lw.goal_receipt(key)
        except LightworkError as exc:
            if exc.status == 404:
                continue  # nothing was admitted under this key, so replaying the same key is safe
            raise
        if receipt["state"] == "accepted":
            goal = lw.get_goal(receipt["goal"]["id"])
            if goal["title"] != title.strip()[:200]:
                raise LightworkError(409, "this key belongs to a different request; use a new key for new work")
            return goal
        # "not_dispatched": an admitted draft. Replaying the same key and inputs dispatches it.
    raise LightworkError(None, "the start is not confirmed; read goal_receipt() with this key before anything else")


lw = Lightwork("http://127.0.0.1:8765")
key = str(uuid.uuid4())  # persist this before sending

goal = submit_once(
    lw, key, "Compare pgvector and Qdrant", "Write the comparison to report.md.",
    max_dollars=2.0, max_wall_seconds=1800,
)

goal_id, since = goal["id"], 0
deadline = time.monotonic() + 3600  # stop waiting; the goal keeps running
while time.monotonic() < deadline:
    page = lw.goal_events(goal_id, since=since)
    for event in page["events"]:
        print(event)
    since = page["next_id"]
    if page["terminal"] and not page["has_more"]:
        break
    if not page["has_more"]:
        time.sleep(2)
else:
    raise TimeoutError(f"goal {goal_id} is not finished; read it later with get_goal()")

final = lw.get_goal(goal_id)
print(final["status"], final["result"])
```

A goal ID means the start was accepted. It does not mean the work ran or
succeeded. `terminal` on the events page is the signal to stop polling. A goal
that waits for an answer keeps `terminal` false and reports `needs_input` and
`open_question_ids`. Answer it with `answer_question()`, then keep polling.

### Recover an uncertain start

`submit_once()` relies on these answers from `goal_receipt(key)`:

| Answer | Meaning | What `submit_once()` does |
|---|---|---|
| `state: "accepted"` | The goal exists and is no longer a draft. | Returns that goal, after checking that its title matches the request. |
| `state: "not_dispatched"` | The goal was admitted as a draft and never started. | Replays `submit_goal()` with the same key and inputs. The replay starts it, once. |
| 404 | No receipt is visible for this key yet. The first request may still be in flight. | Replays with the same key. That is safe: one key maps to one goal. |
| 409 | The receipt's goal row is missing. | Raises. Reconcile on the server; a new key would duplicate the work. |

A 409 from `submit_goal()` is a recovery signal, not a refusal: the server kept
the request under this key and asks you to reconcile before retrying. A key
that was used for different content also gets a 409. The receipt then describes
the earlier request, which is why `submit_once()` compares titles and raises
rather than return the other goal. Replays need the same inputs; changing them
under the same key is a conflict, not a new start.

## Methods

| Method | Dashboard route | Key scope | Returns |
|---|---|---|---|
| `health()` | `GET /healthz` | none (no auth) | `Health(ok, http_status, body)`. A 503 "degraded" answer is returned, not raised. |
| `submit_goal(title, description="", *, max_dollars, max_wall_seconds, max_depth, idempotency_key)` | `POST /api/v1/goals` | `tasks:write` | The goal dict (201). A 409 can mean "reconcile": see above. |
| `goal_receipt(idempotency_key, *, kind="api")` | `GET /api/v1/goal-submissions/receipt` | `tasks:write` | The receipt: `state`, `goal`, `limits`, `execution_confirmed` (always false). It never submits work. |
| `get_goal(goal_id)` | `GET /api/v1/goals/{id}` | any key, for goals you can open | The goal dict, with `status`, `result`, `reason_code`, `needs_input`. |
| `list_goals(*, status, limit=50, offset=0)` | `GET /api/v1/goals` | any key; only goals you can open | A list of goal dicts, newest first. |
| `goal_events(goal_id, *, since=0, limit=200)` | `GET /api/v1/goals/{id}/events` | any key, for goals you can open | One page: `events`, `next_id`, `has_more`, `terminal`, `needs_input`. |
| `answer_question(goal_id, question_id, answer)` | `POST /api/v1/goals/{id}/answer` | `tasks:write` | `None` (204). |
| `list_approvals()` | `GET /api/v1/approvals` | `approvals:decide` (or the operator role when signed in) | The dict from the route, with `approvals` and `private_requests`. |
| `approve_approval(approval_id, *, binding, acknowledged=False, confirmation=None)` | `POST /api/v1/approvals/{id}/approve` | `approvals:decide` | `Decision` (202 or 204). |
| `deny_approval(approval_id, *, reason=None)` | `POST /api/v1/approvals/{id}/deny` | `approvals:decide` | `Decision` (202 or 204). |
| `spend()` | `GET /api/v1/spend` | any key | The dict from the route, with `total` and `episodes`. |

Key scopes are described in
[`docs/api.md`](../../docs/api.md#api-keys-recommended-for-scripts-and-integrations).
A key can never do more than its owner's current role. The server answers a call
outside the key's scope with 403 ("This API key does not have a scope that allows
this."), and the client raises `LightworkError` with that status. The client does
not check scopes itself. Every scope includes read access. The dashboard token is
break-glass access and has no scopes.

Responses are returned as the API sends them: plain dicts and lists. `Health`
and `Decision` are small frozen dataclasses. `Decision` holds the
`X-Lightwork-*` headers: `decision_id`, `audit` (`"delivered"` or `"pending"`)
and `approval_state`. While `audit` is `"pending"`, the vote is recorded but not
yet effective.

### Approving

`binding` is the `binding_sha256` of the reviewed card. Read it from the row
that `list_approvals()` returns, under `approval_card`. The server rejects an
approval without the current card (409). High and critical risk need
`acknowledged=True`; critical risk also needs `confirmation="approve"`. Without
them the server answers 422 and the approval stays pending. Only approve after a
person has reviewed the card.

```python
for row in lw.list_approvals()["approvals"]:
    card = row["approval_card"]
    if card and row["approval_card_status"] == "current":
        print(row["id"], row["action"], row["risk"], row["detail"])
# Approve only after review, for example:
# lw.approve_approval(row["id"], binding=card["binding_sha256"], acknowledged=True)
```

## Errors

Any failed request raises `LightworkError`:

- `exc.status` is the HTTP status. It is `None` when no response arrived: a
  connection failure, a timeout, or a response that was cut short.
- `exc.message` is the server's plain `detail` text. It is never the raw body.
- A token that appears in a server reply is replaced with `[redacted]`.

A 409 from `submit_goal()` is not a refusal. It can mean the request was kept
under its key and needs reconciling. See
[Recover an uncertain start](#recover-an-uncertain-start).

The client never retries a write. A timeout, a cut-off response or a 5xx on a
write can still mean the write happened. For a goal start, recover with
`goal_receipt()` and the same key. For other writes, read the object again before
repeating the action.

## Timeouts and proxies

`timeout` is in seconds (default `30.0`) and applies to each request. It must be
positive. The built-in transport does not follow redirects, so a bearer token is
never re-sent to another URL. A 3xx reply raises `LightworkError`.

Loopback addresses (`localhost`, `127.0.0.1`, `::1`) never go through a proxy,
even when `HTTP_PROXY` or `HTTPS_PROXY` is set, so a token is not sent to a proxy
in clear text. Other hosts use the standard proxy environment variables, including
`NO_PROXY`. To route differently, pass your own `transport=`.

## Testing without a network

Pass `transport=` to replace the network call. A transport receives
`(method, url, headers, body, timeout)` and returns
`(status, response_headers, body_bytes)`.

```python
from lightwork_client import Lightwork

def canned(method, url, headers, body, timeout):
    return 200, {}, b'{"total": 0, "episodes": []}'

assert Lightwork("http://testserver", transport=canned).spend()["total"] == 0
```

The dashboard tests use this seam to run every method against the real app:
`packages/maverick-dashboard/tests/test_python_client.py`.

## Not included

- No async API, no retries, no automatic pagination helpers.
- No server-sent events or WebSocket streams. Use `goal_events()` polling.
- Only the operations listed above. For anything else, use the endpoints in
  `docs/api.md` or the OpenAPI spec.
