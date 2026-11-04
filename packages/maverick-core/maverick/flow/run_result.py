"""Map workflow control signals to wire-compatible durable run results."""
from __future__ import annotations

from ..audit.errors import AuditRefused
from ..budget import BudgetExceeded
from ..killswitch import Halted
from .ir import Flow
from .run_events import (
    FlowApprovalStale,
    FlowBudgetExceeded,
    FlowCredentialRefused,
    _Indeterminate,
    _NodeError,
    _Pause,
    _Reject,
    _safe_error_text,
)
from .run_state import (
    STATUS_BUDGET_LIMITED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_INDETERMINATE,
    STATUS_PAUSED_APPROVAL,
    STATUS_PAUSED_DELAY,
    STATUS_PAUSED_EVENT,
    STATUS_REJECTED,
    FlowRunResult,
)


def execute_chain_result(flow: Flow, data: dict, ctx, start: str | None, *, run_chain, render) -> FlowRunResult:
    try:
        run_chain(flow, data, ctx, start)
        return FlowRunResult(status=STATUS_COMPLETED, data=data)
    except _Pause as p:
        status = {"approval": STATUS_PAUSED_APPROVAL,
                  "event": STATUS_PAUSED_EVENT}.get(p.kind, STATUS_PAUSED_DELAY)
        prompt = p.node.prompt
        if p.kind in {"approval", "event"}:
            from .redact import redact

            try:
                # This snapshot is what the person sees and approves. Never
                # interpolate a credential from the unredacted execution data.
                prompt = redact(render(prompt, redact(p.data, strict=True)),
                                strict=True)
            except ValueError:
                return FlowRunResult(
                    status=STATUS_FAILED, data=p.data, cursor=p.node.id,
                    error="Could not safely prepare the review question.",
                )
        return FlowRunResult(status=status, data=p.data, cursor=p.node.id,
                             resume_at=p.resume_at, prompt=prompt)
    except _Reject as r:
        return FlowRunResult(status=STATUS_FAILED if r.error else STATUS_REJECTED,
                             data=r.data, cursor=r.node.id, error=r.error)
    except _NodeError as e:  # an executor blew up inside a known node -- keep the
        # node id as the cursor so the run can be retried from right there.
        return FlowRunResult(status=STATUS_FAILED, data=data,
                              error=_safe_error_text(e, limit=2000),
                              cursor=ctx.frame.get("cursor") or e.node_id,
                              continuation={"version": 1, "frame": ctx.frame})
    except _Indeterminate as e:
        return FlowRunResult(status=STATUS_INDETERMINATE, data=data,
                              error=_safe_error_text(e, limit=2000),
                              cursor=e.node_id)
    except FlowBudgetExceeded as e:
        return FlowRunResult(
            status=STATUS_BUDGET_LIMITED, data=data, cursor=ctx.frame.get("cursor"),
            error=_safe_error_text(e, limit=2000),
            continuation={"version": 1, "frame": ctx.frame},
        )
    except FlowCredentialRefused as exc:
        # A policy refusal is not a retryable business failure or a catchable
        # scope error. Keep the saved definition/data for explicit migration.
        return FlowRunResult(status=STATUS_FAILED, data=data, error=str(exc))
    except (BudgetExceeded, Halted, FlowApprovalStale, AuditRefused):
        raise
    except Exception as e:  # a node executor blew up -> surface, don't crash the caller
        return FlowRunResult(
            status=STATUS_FAILED, data=data,
            error=_safe_error_text(e, limit=2000),
        )
