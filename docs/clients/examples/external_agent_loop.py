"""Maintained advisory screen/approval example. Never run on import.

For enforced writes use the gateway's execute/commit endpoints instead. The
screen-then-act path cannot make an external effect atomic with authorization.
"""
from __future__ import annotations

import json
import math
import re
import time


def authorize(lw, tool: str, args: dict, *, risk="medium", wait_seconds=60,
              heartbeat=lambda: True, clock=time.monotonic, now=time.time,
              sleep=time.sleep) -> dict:
    # The copied input is the exact input that was screened and may be executed.
    detail = json.dumps(args, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(detail) > 4000:
        raise PermissionError("The action is too large for a reviewed screen request")
    reviewed = json.loads(detail)
    verdict = lw.screen(tool, detail=detail, risk=risk)
    if verdict.get("requires_approval") is not True:
        if verdict.get("allowed") is True:
            return reviewed
        raise PermissionError("Action denied by governance")
    approval_id = verdict.get("approval_id")
    binding = verdict.get("approval_binding_sha256")
    if isinstance(approval_id, bool) or not isinstance(approval_id, int) or approval_id <= 0 or not isinstance(binding, str) or re.fullmatch(r"[a-f0-9]{64}", binding) is None:
        raise PermissionError("The approval binding could not be verified")
    deadline = clock() + max(0, min(wait_seconds, 300))
    while clock() < deadline:
        if not heartbeat():
            raise PermissionError("Work was halted while waiting for approval")
        approval = lw.approval(approval_id, binding)  # 409/stale propagates, never acts.
        if approval.get("approval_id") != approval_id or approval.get("approval_binding_sha256") != binding:
            raise PermissionError("The reviewed action changed")
        expires = approval.get("expires_at")
        if not isinstance(expires, (int, float)) or isinstance(expires, bool) or not math.isfinite(expires) or expires <= now():
            raise PermissionError("Approval expired or its expiry could not be verified")
        if approval.get("status") == "approved":
            return reviewed
        if approval.get("status") != "pending":
            raise PermissionError("Approval was denied or is no longer available")
        sleep(min(2, max(0, deadline - clock())))
    raise PermissionError("Approval is still pending; no action was performed")


def run_tool_loop(lw, complete, send_email, messages, *, max_turns=32, authorize_action=authorize):
    """Call complete(messages) for a chat message; finish once with an honest outcome."""
    started = lw.start("Q3 summary email", department="finance")
    goal_id = started["goal_id"]
    outcome, reason, summary, calls = "failure", "turn limit reached", "", 0
    blocked = False
    try:
        for _ in range(max_turns):
            if not lw.heartbeat(goal_id):
                reason = "halted at a work checkpoint"
                break
            msg = complete(messages)
            if not msg.tool_calls:
                summary = (msg.content or "")[:4000]
                outcome = "failure" if blocked else "success"
                reason = "action blocked by governance" if blocked else "completed"
                break
            messages.append(msg)
            for call in msg.tool_calls:
                if call.function.name != "send_email":
                    raise PermissionError("Unsupported tool requested")
                args = json.loads(call.function.arguments)
                if not isinstance(args, dict) or set(args) != {"to", "body"} or not all(isinstance(value, str) for value in args.values()):
                    raise ValueError("Invalid email arguments")
                reviewed = authorize_action(lw, call.function.name, args,
                                     heartbeat=lambda: lw.heartbeat(goal_id))
                if not lw.heartbeat(goal_id):
                    reason = "halted before external action"
                    blocked = True
                    break
                result = send_email(**reviewed)
                calls += 1
                messages.append({"role": "tool", "tool_call_id": call.id, "content": str(result)})
            if blocked:
                break
    except PermissionError:
        reason = "action denied, pending, expired, stale or halted; no further work performed"
    except Exception as exc:
        # Do not copy provider errors, arguments, credentials or email contents.
        reason = "interrupted by " + type(exc).__name__ + "; effect outcome may require reconciliation"
    receipt = lw.finish(goal_id, outcome, summary=summary or reason, steps=[reason],
                        tool_calls=calls, idempotency_key=f"q3-email-{goal_id}")
    return {"outcome": outcome, "reason": reason, "receipt": receipt}
