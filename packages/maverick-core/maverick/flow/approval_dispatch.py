"""Revalidate approval authority and durably claim the first external effect."""
from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from . import store
from .ir import Flow, FlowNode
from .run_events import FlowApprovalStale
from .run_state import STATUS_RESUMING


class ApprovalDispatch:
    """Own the approval recheck and at-most-once durable resume claim.

    The run lock remains the caller's responsibility. This class keeps the
    authority fence across validation, checkpoint publication and the actual
    action, including later actions reached by a single approved continuation.
    """

    def __init__(self, *, action_runner: Callable[..., Any], flow: Flow,
                 prior: store.FlowRun | None, snapshot: store.FlowRun | None,
                 approval_resume: bool, submitted_inputs: dict, binding: str,
                 authority_binding: str, decision: str, actor: str, expired: bool,
                 decision_attestation: object | None):
        self.action_runner = action_runner
        self.flow = flow
        self.prior = prior
        self.snapshot = snapshot
        self.approval_resume = approval_resume
        self.submitted_inputs = submitted_inputs
        self.binding = binding
        self.authority_binding = authority_binding
        self.decision = decision
        self.actor = actor
        self.expired = expired
        self.decision_attestation = decision_attestation
        self._claimed = False
        self._admitted_at = 0.0
        self._claim_lock = threading.Lock()

    def __call__(self, node: FlowNode, params: dict, data: dict) -> Any:
        if not self.approval_resume:
            return self.action_runner(node.tool, params, data)
        # Mutations to authority share this fence with the provider boundary.
        with self._admitted():
            return self.action_runner(node.tool, params, data)

    def admit_agent(self) -> None:
        """Recheck authority and claim the resume before an agent step.

        An agent goal may have side effects, so an approved continuation must
        be durably claimed before it starts, exactly as before an action.  The
        fence is released before the (possibly long) agent runs.
        """
        if not self.approval_resume:
            return
        with self._admitted():
            pass

    @contextmanager
    def _admitted(self) -> Iterator[None]:
        if self.snapshot is None or self.prior is None:
            raise RuntimeError("approval resume is missing its durable run or reviewed snapshot")

        from ..approval_cards import ApprovalCardError
        from ..authority_effects import authority_effect_fence
        from .approvals import require_current_paused_operation

        # A failed validation before the first claim leaves the pause intact;
        # a later failure is quarantined by the outer durable run guard.
        with authority_effect_fence():
            # Freshness (card and decision expiry) is judged once, when the
            # continuation is admitted and claimed.  Later effects of the same
            # claimed continuation recheck every authority binding against the
            # live state, but against that admission time, so a long agent step
            # cannot turn a valid approval into a half-executed run.
            checked_at = self._admitted_at if self._claimed else time.time()
            try:
                require_current_paused_operation(
                    self.snapshot,
                    self.flow,
                    inputs=self.submitted_inputs,
                    expected_binding=self.binding,
                    authority_binding_sha256=self.authority_binding,
                    decision=self.decision,
                    decided_by=self.actor,
                    expired=self.expired,
                    decision_attestation=self.decision_attestation,
                    now=checked_at,
                )
            except ApprovalCardError as exc:
                raise FlowApprovalStale(
                    "Approval authority changed before execution. Review the current operation again."
                ) from exc
            with self._claim_lock:
                if not self._claimed:
                    self.prior.status = STATUS_RESUMING
                    if not self.expired:
                        self.prior.decided_by = self.actor
                    store.save_run(self.prior)
                    self._admitted_at = checked_at
                    self._claimed = True
            yield
