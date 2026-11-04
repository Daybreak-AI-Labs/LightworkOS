"""Tenant-local promotion of a reviewed evidence renewal step into a flow.

This deliberately small first case runs actual existing branch/setvar/scope
nodes. Human observations, held-out labels, evaluation and promotion are
separate durable records. The baseline is an offline deterministic stand-in
for an agent/human procedure; timings do not establish LLM or labor savings.
"""
from __future__ import annotations

import functools
import math
import threading
import time
import uuid
from dataclasses import asdict, dataclass

from .file_lock import cross_process_lock
from .flow import enabled as flows_enabled
from .flow import store
from .flow.evolve import harden_evidence_renewal
from .flow.ir import NODE_AGENT, Flow, FlowNode
from .flow.runner import run_flow
from .governed_operations import ServiceContext, digest
from .governed_records import GovernedRecordStore
from .paths import data_dir, tenant_scope
from .vendor_onboarding import enabled

_OBSERVATIONS = GovernedRecordStore("vendor_renewal_observations", "VEO", "vendor_renewal_observation")
_CANDIDATES = GovernedRecordStore("vendor_renewal_candidates", "VEC", "vendor_renewal_candidate")
_ACTIVE = GovernedRecordStore("vendor_renewal_activation", "VEA", "vendor_renewal_activation")
_LOCK = threading.RLock()
BINDINGS = {"due_at": "due_at", "now": "now"}


@dataclass(frozen=True)
class RenewalInputs:
    due_at: float
    now: float
    evidence_status: str
    source_version: str
    expected_source_version: str
    downstream_version: str
    expected_downstream_version: str
    customer_accepted: bool

    def __post_init__(self):
        for name in ("due_at", "now"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError("renewal times must be positive finite numbers")
        if type(self.customer_accepted) is not bool:
            raise ValueError("customer_accepted must be a boolean")
        for name in ("evidence_status", "source_version", "expected_source_version",
                     "downstream_version", "expected_downstream_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError("renewal evidence bindings must be bounded strings")

    def eligible(self):
        return (self.evidence_status == "available" and self.customer_accepted
                and self.source_version == self.expected_source_version
                and self.downstream_version == self.expected_downstream_version)


def baseline_renewal_review(values: dict, *, bindings: dict | None = None) -> str:
    """Explicit offline stand-in for a reviewed agent/human procedure."""
    if bindings is not None and bindings != BINDINGS:
        return "human_fallback"
    try:
        typed = RenewalInputs(**values)
    except (TypeError, ValueError):
        return "human_fallback"
    if not typed.eligible():
        return "human_fallback"
    return "renewal_due" if typed.now >= typed.due_at else "fresh"


def _base(flow_id, owner):
    return Flow(id=flow_id, name="Vendor evidence renewal", start="renewal", owner=owner, nodes={
        "renewal": FlowNode(id="renewal", kind=NODE_AGENT,
                            brief="Review current evidence freshness and renewal requirement",
                            output="classification"),
    })


def _definition_digest(flow):
    value = flow.to_dict()
    value.pop("revision", None)
    value.pop("version", None)
    return digest(value)


def _evaluation_coverage(cases):
    """Validate actual test content; labels alone cannot satisfy safety gates."""
    covered = set()
    held_out_classes = set()
    for case in cases:
        category = case.get("category")
        bindings = case.get("bindings", BINDINGS)
        try:
            value = RenewalInputs(**case["inputs"])
        except (TypeError, ValueError):
            if category == "invalid_inputs" and bindings == BINDINGS:
                covered.add(category)
            continue
        if category == "invalid_bindings" and bindings != BINDINGS and value.eligible():
            covered.add(category)
        if (category == "changed_downstream" and bindings == BINDINGS
                and value.downstream_version != value.expected_downstream_version):
            covered.add(category)
        if category == "changed_inputs" and bindings == BINDINGS:
            covered.add(category)
        if category == "held_out" and bindings == BINDINGS and value.eligible():
            held_out_classes.add(baseline_renewal_review(case["inputs"]))
    if held_out_classes == {"fresh", "renewal_due"}:
        covered.add("held_out")
    required = {"held_out", "changed_inputs", "invalid_bindings", "changed_downstream", "invalid_inputs"}
    if not required.issubset(covered):
        raise ValueError("evaluation content does not exercise required semantic coverage")


def execute_candidate(flow: Flow, values: dict, *, bindings: dict) -> str:
    """Run restricted graph after typed source/precondition guards, or fall back."""
    try:
        typed = RenewalInputs(**values)
        if bindings != BINDINGS or not typed.eligible():
            return "human_fallback"
        expected = harden_evidence_renewal(_base(flow.id, flow.owner), bindings=BINDINGS)
        if _definition_digest(flow) != _definition_digest(expected):
            return "human_fallback"
    except (TypeError, ValueError):
        return "human_fallback"

    def forbidden(*args):
        raise PermissionError("renewal candidate cannot execute tools or agent calls")

    result = run_flow(flow, data=asdict(typed), agent_fn=forbidden, action_fn=forbidden)
    if result.status != "completed":
        return "human_fallback"
    return result.data.get("classification", "human_fallback")


def _scoped(method):
    @functools.wraps(method)
    def invoke(self, ctx, *args, **kwargs):
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        if not enabled():
            raise RuntimeError("vendor onboarding is disabled")
        with tenant_scope(tenant=ctx.tenant):
            with _LOCK, cross_process_lock(data_dir("vendor_renewal", "promotion"), strict=True):
                return method(self, ctx, *args, **kwargs)
    return invoke


class EvidenceRenewalEvolution:
    def __init__(self, authorize, *, clock=time.time):
        self.authorize, self.clock = authorize, clock

    def _permit(self, ctx, capability, *, human=False):
        if (human and not ctx.human) or self.authorize(ctx, capability, ctx.resource_owner) is not True:
            raise PermissionError("renewal evolution requires explicit authorized human decision"
                                  if human else "renewal evolution permission denied")

    def _owned(self, row, ctx):
        if not row or row.get("tenant") != ctx.tenant or row.get("owner") != ctx.resource_owner:
            raise KeyError("renewal record not found")
        return row

    def _record_observation(self, ctx, typed, reviewed_output, rationale, provenance):
        if reviewed_output not in {"fresh", "renewal_due", "human_fallback"}:
            raise ValueError("unsupported reviewed renewal output")
        if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 4000:
            raise ValueError("bounded review rationale required")
        return _OBSERVATIONS.create({
            "id": _OBSERVATIONS.new_id(), "tenant": ctx.tenant, "owner": ctx.resource_owner,
            "inputs": asdict(typed), "input_sha256": digest(asdict(typed)),
            "output": reviewed_output, "reviewer": ctx.actor, "rationale": rationale,
            "observed_at": self.clock(), "material_policy": "tenant_local; no cross_customer_pooling",
            **provenance, "source_provenance_sha256": digest(provenance),
        }, action="review_renewal_observation", actor=ctx.actor, max_records=10000)

    @_scoped
    def observe(self, ctx, values, reviewed_output, *, source_case_id, source_workflow_version, rationale):
        """Low-level caller-supplied observation; production uses observe_case.

        Kept for internally authored fixtures and compatibility. Its provenance
        explicitly does not attest that the caller's source references exist.
        """
        self._permit(ctx, "renewal.observe", human=True)
        typed = RenewalInputs(**values)
        if not source_case_id or not source_workflow_version or not rationale:
            raise ValueError("source case, workflow version and review rationale required")
        return self._record_observation(ctx, typed, reviewed_output, rationale, {
            "capture_origin": "caller_supplied_observation", "source_case_id": source_case_id,
            "source_workflow_version": source_workflow_version,
        })

    @_scoped
    def observe_case(self, ctx, service, case_id, reviewed_output, *, rationale):
        """Capture a human-reviewed step from accepted records and current providers.

        Callers supply the human output and rationale, never freshness inputs,
        source versions, digests, assessment identity or workflow provenance.
        """
        self._permit(ctx, "renewal.observe", human=True)
        typed, provenance = self._case_inputs(ctx, service, case_id)
        return self._record_observation(ctx, typed, reviewed_output, rationale, provenance)

    @_scoped
    def propose(self, ctx, observation_ids, *, bindings, rationale):
        self._permit(ctx, "renewal.propose", human=True)
        if bindings != BINDINGS or not rationale:
            raise ValueError("exact typed bindings and review rationale required")
        if not isinstance(observation_ids, list) or len(set(observation_ids)) < 3:
            raise ValueError("at least three distinct reviewed observations required")
        observations = [self._owned(_OBSERVATIONS.get(key), ctx) for key in observation_ids]
        if len({item["input_sha256"] for item in observations}) < 3:
            raise ValueError("observations must cover distinct input cases")
        flow = harden_evidence_renewal(_base("vendor-renewal-" + uuid.uuid4().hex, ctx.actor),
                                      bindings=bindings)
        for observation in observations:
            if execute_candidate(flow, observation["inputs"], bindings=bindings) != observation["output"]:
                raise ValueError("candidate disagrees with reviewed observations; retain fallback")
        return _CANDIDATES.create({
            "id": _CANDIDATES.new_id(), "tenant": ctx.tenant, "owner": ctx.resource_owner,
            "state": "proposed", "flow": flow.to_dict(), "flow_sha256": _definition_digest(flow),
            "bindings": dict(bindings), "bindings_reviewed_by": ctx.actor, "rationale": rationale,
            "observation_ids": observation_ids,
            "training_input_sha256": [item["input_sha256"] for item in observations],
            "evaluation": None, "permission_change": "none", "fallback": "human_review",
        }, action="propose_renewal_candidate", actor=ctx.actor, max_records=1000)

    @_scoped
    def evaluate(self, ctx, candidate_id, cases):
        self._permit(ctx, "renewal.evaluate", human=True)
        candidate = self._owned(_CANDIDATES.get(candidate_id), ctx)
        if candidate["state"] != "proposed":
            raise ValueError("only proposed candidates can be evaluated")
        if not isinstance(cases, list) or not 5 <= len(cases) <= 1000:
            raise ValueError("provide between five and 1000 held-out cases")
        expected_labels = {"fresh", "renewal_due", "human_fallback"}
        required = {"held_out", "changed_inputs", "invalid_bindings", "changed_downstream", "invalid_inputs"}
        if not required.issubset({case.get("category") for case in cases}):
            raise ValueError("evaluation must cover held-out, changed, invalid and downstream cases")
        hashes = [digest(case["inputs"]) for case in cases]
        if len(set(hashes)) != len(hashes):
            raise ValueError("held-out evaluation inputs must be distinct")
        if set(hashes).intersection(candidate["training_input_sha256"]):
            raise ValueError("held-out cases overlap training observations")
        if any(case.get("material") != "internally_authored_synthetic" for case in cases):
            raise ValueError("reusable evaluation currently supports internally authored synthetic cases only")
        if any(case.get("expected") not in expected_labels for case in cases):
            raise ValueError("held-out cases require reviewed output labels")
        _evaluation_coverage(cases)
        flow = Flow.from_dict(candidate["flow"])
        rows, baseline_elapsed, candidate_elapsed = [], 0.0, 0.0
        for case in cases:
            started = time.perf_counter()
            baseline = baseline_renewal_review(case["inputs"], bindings=case.get("bindings", candidate["bindings"]))
            baseline_elapsed += time.perf_counter() - started
            started = time.perf_counter()
            result = execute_candidate(flow, case["inputs"], bindings=case.get("bindings", candidate["bindings"]))
            candidate_elapsed += time.perf_counter() - started
            rows.append({"id": case["id"], "category": case["category"], "inputs": case["inputs"],
                         "input_sha256": digest(case["inputs"]), "expected": case["expected"],
                         "baseline": baseline, "candidate": result, "passed": result == case["expected"],
                         "binding_sha256": digest(case.get("bindings", candidate["bindings"]))})
        report = {"n": len(rows), "passed": sum(row["passed"] for row in rows), "cases": rows,
                  "baseline_correct": sum(row["baseline"] == row["expected"] for row in rows),
                  "baseline_seconds": baseline_elapsed, "candidate_seconds": candidate_elapsed,
                  "baseline_kind": "offline deterministic stand-in for agent/human procedure",
                  "comparison": "paired same input and binding guards; no model baseline",
                  "model_calls": 0, "execution_cost_usd": 0.0,
                  "limitations": "Synthetic labels and microtimings; no model, labor or customer savings measured.",
                  "reviewer": ctx.actor, "evaluated_at": self.clock()}
        return _CANDIDATES.update(candidate_id, lambda row: row.update(evaluation=report),
                                  expected_revision=candidate["revision"],
                                  action="evaluate_renewal_candidate", actor=ctx.actor)

    @_scoped
    def promote(self, ctx, candidate_id, expected_revision, *, rationale):
        self._permit(ctx, "renewal.promote", human=True)
        if not flows_enabled():
            raise RuntimeError("renewal promotion requires [flows] enable = true")
        candidate = self._owned(_CANDIDATES.get(candidate_id), ctx)
        if candidate["revision"] != expected_revision or not rationale:
            raise ValueError("candidate revision and promotion rationale required")
        evaluation = candidate.get("evaluation") or {}
        if not evaluation.get("n") or evaluation.get("passed") != evaluation["n"]:
            raise ValueError("passing held-out evaluation required")
        flow = Flow.from_dict(candidate["flow"])
        expected = harden_evidence_renewal(_base(flow.id, flow.owner), bindings=BINDINGS)
        if (candidate["bindings"] != BINDINGS or _definition_digest(flow) != candidate["flow_sha256"]
                or _definition_digest(flow) != _definition_digest(expected)):
            raise ValueError("candidate definition digest changed")
        current = store.load_flow(flow.id)
        if current is None:
            # Preserve actual baseline definition as version 1 for rollback.
            current = store.save_flow(_base(flow.id, flow.owner), expected_version=0)
        saved = store.save_flow(flow, expected_version=current.version, expected_revision=current.revision)
        pointer = _ACTIVE.get("VEA-current")
        if pointer:
            self._owned(pointer, ctx)
        activation = {"candidate_id": candidate_id, "candidate_revision": candidate["revision"],
                      "evaluation_sha256": digest(evaluation),
                      "bindings_sha256": digest(candidate["bindings"]),
                      "flow_id": saved.id, "version": saved.version,
                      "revision": saved.revision, "flow_sha256": _definition_digest(saved),
                      "promoted_by": ctx.actor, "rationale": rationale, "promoted_at": self.clock()}
        history = list((pointer or {}).get("history") or [])
        if pointer and pointer.get("active"):
            history.append(pointer["active"])
        if pointer:
            result = _ACTIVE.update("VEA-current", lambda row: row.update(active=activation, history=history),
                                    expected_revision=pointer["revision"],
                                    action="promote_renewal_definition", actor=ctx.actor)
        else:
            result = _ACTIVE.create({"id": "VEA-current", "tenant": ctx.tenant,
                                     "owner": ctx.resource_owner, "active": activation, "history": history},
                                    action="promote_renewal_definition", actor=ctx.actor)
        return result

    @_scoped
    def rollback(self, ctx, expected_revision, *, rationale):
        self._permit(ctx, "renewal.promote", human=True)
        pointer = self._owned(_ACTIVE.get("VEA-current"), ctx)
        if pointer["revision"] != expected_revision or not rationale:
            raise ValueError("current activation revision and rollback rationale required")
        active = pointer.get("active")
        if not active:
            raise ValueError("no active definition to roll back")
        saved = store.rollback_flow(active["flow_id"], version=1,
                                    expected_version=active["version"], expected_revision=active["revision"])
        if saved is None:
            raise ValueError("baseline workflow definition unavailable")
        return _ACTIVE.update("VEA-current", lambda row: row.update(
            active=None, history=[*row["history"], dict(active, rolled_back_by=ctx.actor,
                                                       rollback_rationale=rationale,
                                                       rollback_version=saved.version)]),
            expected_revision=pointer["revision"], action="rollback_renewal_definition", actor=ctx.actor)

    @_scoped
    def run(self, ctx, values):
        self._permit(ctx, "renewal.run")
        if not flows_enabled():
            return {"classification": "human_fallback", "reason": "flow execution disabled"}
        pointer = _ACTIVE.get("VEA-current")
        if not pointer:
            return {"classification": "human_fallback", "reason": "no human-promoted definition"}
        self._owned(pointer, ctx)
        active = pointer.get("active")
        if not active:
            return {"classification": "human_fallback", "reason": "definition rolled back"}
        flow = store.load_flow(active["flow_id"])
        if (flow is None or flow.version != active["version"] or flow.revision != active["revision"]
                or _definition_digest(flow) != active["flow_sha256"]):
            return {"classification": "human_fallback", "reason": "definition changed or unavailable"}
        classification = execute_candidate(flow, values, bindings=BINDINGS)
        return {"classification": classification, "flow_id": flow.id, "workflow_version": flow.version,
                "candidate_id": active["candidate_id"], "reason": "typed precondition checks and flow execution"}

    def _case_inputs(self, ctx, service, case_id):
        """Shared authoritative typed input capture for observation and execution."""
        from . import ai_vendor_risk, vendor_management

        row = service.get(ctx, case_id)
        outcome, evidence, operation = row.get("outcome") or {}, row.get("evidence") or {}, row.get("operation") or {}
        if outcome.get("accepted") is not True or operation.get("state") != "verified":
            raise ValueError("customer acceptance and verified execution required")
        if ctx.binding() != operation["context"]:
            raise PermissionError("accepted operation credential authority changed")
        if (evidence.get("status") != "available" or evidence.get("source") not in {"gdrive", "upload", "evidence_set"}
                or evidence.get("content_sha256") != outcome.get("evidence_sha256")
                or evidence.get("content_sha256") != operation["preconditions"].get("evidence_sha256")
                or outcome.get("renewal_due_at") != evidence.get("fresh_until")
                or outcome.get("workflow_schema") != row["schema"]
                or outcome.get("operation_id") != operation["id"]
                or digest(operation["payload"]) != operation["payload_sha256"]):
            raise ValueError("accepted evidence or operation provenance changed")
        with tenant_scope(tenant=ctx.tenant):
            service._permit(ctx, "evidence.read", case_id)
            service._permit(ctx, "action.reconcile", case_id)
            assessment = ai_vendor_risk.get_vendor_assessment(outcome["assessment_id"])
            if (assessment is None or assessment["status"] != "approved"
                    or assessment["assessment_sha256"] != outcome.get("assessment_sha256")
                    or assessment["id"] != row["assessment"]["id"]
                    or assessment["revision"] != row["assessment"]["revision"]
                    or assessment["revision"] != operation["preconditions"].get("assessment_revision")):
                raise ValueError("accepted assessment identity or revision changed")
            vendor = vendor_management.get_vendor(row["vendor_id"])
            if not vendor or vendor["owner"] != ctx.resource_owner or vendor["status"] == "offboarded":
                raise PermissionError("vendor ownership or lifecycle changed")
            source_version = service.current_evidence_version(ctx, row, verify_bytes=True)
            if source_version != evidence["version"]:
                raise ValueError("accepted source evidence bytes or version changed")
            confirmation = service.tickets.verify(
                ctx, operation["external_confirmation"]["key"], operation["payload"],
                expected_credential_version=operation["preconditions"]["ticket_credential_version"],
            )
        versions = (confirmation.get("external_version"),
                    operation["external_confirmation"].get("external_version"))
        if confirmation.get("verified") is not True or not all(isinstance(v, str) and v for v in versions):
            raise ValueError("downstream confirmation or version evidence unavailable")
        if versions[0] != versions[1]:
            raise ValueError("accepted downstream version changed")
        # Detect a case mutation while provider reads were in flight; accepted
        # cases ordinarily cannot be edited through the application service.
        if service.get(ctx, case_id)["revision"] != row["revision"]:
            raise ValueError("accepted case changed during evidence capture")
        typed = RenewalInputs(
            outcome["renewal_due_at"], self.clock(), evidence["status"], source_version,
            evidence["version"], versions[0], versions[1], True,
        )
        provenance = {
            "capture_origin": "accepted_vendor_case", "source_case_id": row["id"],
            "source_case_revision": row["revision"], "source_workflow_version": outcome["workflow_schema"],
            "source_step": "human_reviewed_evidence_renewal", "evidence_sha256": evidence["content_sha256"],
            "assessment_id": assessment["id"], "assessment_revision": assessment["revision"],
            "assessment_sha256": assessment["assessment_sha256"], "operation_id": operation["id"],
            "external_confirmation": confirmation, "integration_mode": row["integration_mode"],
        }
        return typed, provenance

    def run_for_case(self, ctx, service, case_id):
        """Read authoritative inputs and run a promoted definition or retain review."""
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        self._permit(ctx, "renewal.run")
        if not flows_enabled():
            return {"classification": "human_fallback", "reason": "flow execution disabled"}
        try:
            typed, provenance = self._case_inputs(ctx, service, case_id)
        except (KeyError, PermissionError):
            raise
        except Exception:
            return {"classification": "human_fallback", "reason": "accepted evidence or external verification unavailable or changed"}
        return dict(self.run(ctx, asdict(typed)), source_case_id=case_id,
                    source_case_revision=provenance["source_case_revision"],
                    source_provenance_sha256=digest(provenance))
