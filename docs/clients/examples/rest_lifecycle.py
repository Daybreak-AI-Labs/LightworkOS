"""Bounded REST examples. No work is started on import and writes never retry."""
from __future__ import annotations

import time


class RecoveryRequired(RuntimeError):
    """Keep the original request key; resolve through the receipt lookup."""


def start_or_reconcile(session, base: str, headers: dict, body: dict, request_key: str):
    """Persist request_key before calling; one POST, then only GET on uncertainty."""
    import requests

    bound = {**headers, "Idempotency-Key": request_key}
    if not request_key:
        raise ValueError("Persist a stable request key before starting work")
    try:
        response = session.post(base + "/api/v1/goals", json=body, headers=bound, timeout=15)
    except requests.RequestException:
        # Timeout, reset, or a body cut off mid-response: the server may have accepted it.
        return reconcile(session, base, bound)
    if response.status_code == 409:
        raise RecoveryRequired("The key's reviewed input or effective limits changed. Keep the key and review the original receipt.")
    if response.status_code >= 500:
        return reconcile(session, base, bound)
    if response.status_code in (401, 403):
        raise PermissionError("Restore authorized sign-in before checking this request")
    response.raise_for_status()
    try:
        result = response.json()
    except ValueError:  # a 2xx whose body cannot be read still may have started work
        return reconcile(session, base, bound)
    if not isinstance(result, dict) or isinstance(result.get("id"), bool) or not isinstance(result.get("id"), int) or result["id"] <= 0:
        return reconcile(session, base, bound)
    return {"state": "accepted", "goal": result, "execution_confirmed": False}


def reconcile(session, base: str, headers: dict):
    response = session.get(base + "/api/v1/goal-submissions/receipt", params={"kind": "api"}, headers=headers, timeout=15)
    if response.status_code in (401, 403):
        raise PermissionError("Restore the original authorized account/workspace; keep the request key")
    if response.status_code != 200:
        raise RecoveryRequired("Start remains unconfirmed. Keep the original key; a missing receipt does not prove that no work ran.")
    receipt = response.json()
    if not isinstance(receipt, dict) or receipt.get("execution_confirmed") is not False:
        raise RecoveryRequired("Receipt could not be verified; keep the original key")
    return receipt  # Includes admission/dispatch state; acceptance is not execution.


def poll_events(session, base: str, headers: dict, goal_id: int, emit, *,
                since=0, deadline_seconds=1800, cancelled=lambda: False,
                clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + deadline_seconds
    while not cancelled() and clock() < deadline:
        response = session.get(f"{base}/api/v1/goals/{goal_id}/events",
                               params={"since": since, "limit": 200}, headers=headers, timeout=15)
        if response.status_code in (401, 403):
            raise PermissionError("Polling stopped. Restore sign-in and authorized task access before resuming.")
        response.raise_for_status()
        page = response.json()
        if not isinstance(page, dict):
            raise ValueError("Event page must be an object")
        events, next_id = page.get("events"), page.get("next_id")
        if not isinstance(events, list) or len(events) > 200 or isinstance(next_id, bool) or not isinstance(next_id, int) or next_id < since:
            raise ValueError("Event page could not be verified; keep the last acknowledged cursor")
        if not isinstance(page.get("has_more"), bool) or not isinstance(page.get("terminal"), bool):
            raise ValueError("Event completion acknowledgement is missing")
        prior = since
        # Validate the whole page before displaying any of it; old replay IDs may repeat.
        previous_new = since
        for event in events:
            event_id = event.get("id") if isinstance(event, dict) else None
            if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 0 or event_id > next_id:
                raise ValueError("Event cursor could not be verified")
            if event_id > prior:
                if event_id < previous_new:
                    raise ValueError("Event page is not in replay order")
                previous_new = event_id
        for event in events:
            event_id = event["id"]
            if event_id <= since:
                continue
            emit(event)
            since = event_id  # Advance only after the consumer accepts the event.
        if next_id != since or (page["has_more"] and since == prior):
            raise ValueError("Event cursor did not advance consistently; polling stopped")
        if page["terminal"] and not page["has_more"]:
            return {"terminal": True, "since": since, "status": page.get("status")}
        if not page["has_more"]:
            sleep(min(2, max(0, deadline - clock())))
    return {"terminal": False, "since": since, "reason": "cancelled" if cancelled() else "poll deadline reached"}
