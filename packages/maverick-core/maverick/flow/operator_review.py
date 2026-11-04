"""Tenant-scoped reviewed questions that produce unpublished flow drafts.

One governed record owns the question, reviewed answer, refinement lineage and
draft. No second store is mutated when an answer commits. Existing flow save
and publication controls remain the only deployment authority.
"""
from __future__ import annotations

import copy
import re
import time
from collections.abc import Callable
from typing import Any

from ..audit.errors import AuditRefused
from ..governed_operations import ServiceContext, audit_authority_denial, digest
from ..governed_records import GovernedRecordStore, RecordConflict
from ..paths import tenant_scope
from . import store as flow_store
from .evolve import attach_learned_operator
from .ir import Flow, validate_learned_operator
from .operator_artifacts import candidate_count

SCHEMA = "lightwork.operator-review.v1"
LINEAGE_SCHEMA = "lightwork.operator-refinement.v1"
MAX_RECORDS = 1000
_ID = re.compile(r"LOQ-[0-9a-f]{32}\Z")
_RECORDS = GovernedRecordStore("flow_operator_reviews", "LOQ", "flow_operator_review")


class OperatorReviewConflict(RecordConflict):
    """A question, saved flow generation, or reviewed answer changed."""


class OperatorReviewAuditPending(AuditRefused):
    """The question is durable but its audit receipt is not delivered yet."""

    def __init__(self, question_id: str):
        super().__init__("operator review has a pending audit receipt")
        self.question_id = question_id


def _text(value: object, label: str, maximum: int = 256) -> str:
    if (type(value) is not str or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 for char in value)):
        raise ValueError(f"{label} must be a nonempty bounded string")
    return value


def _revision(value: object) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("expected_revision must be a positive integer")
    return value


def _answer_digest(question: dict, output: Any, rationale: str, reviewer: str) -> str:
    return digest({"question_sha256": question["question_sha256"],
                   "output": output, "rationale": rationale, "reviewer": reviewer})


def _binding(ctx: ServiceContext, flow: Flow, node_id: str) -> dict:
    node = flow.nodes.get(node_id)
    if node is None or node.learned_operator is None:
        raise ValueError("flow node requires an attached learned operator")
    validate_learned_operator(node)
    return {
        "tenant_sha256": digest(ctx.tenant), "owner": flow.owner,
        "flow_id": flow.id, "flow_version": flow.version, "flow_revision": flow.revision,
        "flow_sha256": digest(flow.to_dict()), "node_id": node_id,
        "work_sha256": node.learned_operator["work_sha256"],
        "artifact_sha256": node.learned_operator["artifact"]["artifact_sha256"],
    }


class OperatorReviewService:
    """Use authority supplied by trusted composition, never request-body identity.

    ``authorize(context, capability, flow_id)`` must freshly validate current
    workspace membership, permission and resource ownership, returning literal
    True. ``ServiceContext.human`` alone is not authentication.
    """

    def __init__(self, authorize: Callable, *, records: GovernedRecordStore | None = None,
                 clock: Callable[[], float] = time.time):
        if not callable(authorize) or not callable(clock):
            raise TypeError("authoritative authorization and clock callbacks are required")
        self.authorize = authorize
        self.records = records if records is not None else _RECORDS
        self.clock = clock

    @staticmethod
    def _gate(ctx: ServiceContext) -> None:
        from ..config import get_flows
        from . import enabled

        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        if not enabled() or get_flows().get("learned_operator_questions") is not True:
            raise PermissionError("learned operator questions are disabled")

    def _permit(self, ctx: ServiceContext, capability: str, resource: str, *, human=False) -> None:
        if human and ctx.human is not True:
            audit_authority_denial(ctx, capability, resource, "authenticated_human_required")
            raise PermissionError("this answer requires an authorized human")
        try:
            allowed = self.authorize(ctx, capability, resource)
        except Exception:
            audit_authority_denial(ctx, capability, resource, "current_authority_unavailable")
            raise
        if allowed is not True:
            audit_authority_denial(ctx, capability, resource, "current_authority_denied")
            raise PermissionError("current authority denied operator review")

    @staticmethod
    def _flow(ctx: ServiceContext, flow_id: str) -> Flow:
        flow = flow_store.load_flow(flow_id)
        if flow is None:
            raise LookupError("flow is unavailable")
        if not flow.owner or flow.owner != ctx.resource_owner:
            raise PermissionError("operator review requires the current flow owner")
        if type(flow.version) is not int or flow.version < 1 or not flow.revision:
            raise ValueError("operator review requires a saved flow generation")
        return flow

    def _current(self, ctx: ServiceContext, row: dict) -> Flow:
        bound = row["binding"]
        current = self._flow(ctx, bound["flow_id"])
        if _binding(ctx, current, bound["node_id"]) != bound:
            raise OperatorReviewConflict("source flow changed; request a question for its current revision")
        return current

    @staticmethod
    def _verify(ctx: ServiceContext, row: dict) -> None:
        from .operator_queries import answer_question, validate_question

        if row.get("schema") != SCHEMA or not isinstance(row.get("binding"), dict):
            raise ValueError("invalid operator review record")
        bound = row["binding"]
        if bound.get("tenant_sha256") != digest(ctx.tenant) or bound.get("owner") != ctx.resource_owner:
            raise PermissionError("operator review authority does not match its owner")
        if digest(row["base_flow"]) != bound.get("flow_sha256"):
            raise ValueError("operator review base bytes failed integrity checks")
        base = Flow.from_dict(row["base_flow"])
        if _binding(ctx, base, bound["node_id"]) != bound:
            raise ValueError("operator review base definition failed integrity checks")
        artifact = base.nodes[bound["node_id"]].learned_operator["artifact"]
        validate_question(artifact, row["question"])
        identity = digest({"binding": bound, "question_sha256": row["question"]["question_sha256"]})
        if row.get("id") != "LOQ-" + identity[:32]:
            raise ValueError("operator review identity failed integrity checks")
        query_status = row["question"]["status"]
        if row["status"] == "draft_ready":
            review = row["review"]
            if not isinstance(review, dict) or review.get("human") is not True:
                raise ValueError("operator review has no reviewed answer")
            if set(review) != {"human", "reviewer", "output", "rationale", "reviewed_at",
                               "authority_sha256", "request_sha256"}:
                raise ValueError("invalid operator review fields")
            expected = answer_question(artifact, row["question"], review["output"])
            if review["request_sha256"] != _answer_digest(
                row["question"], review["output"], _text(review["rationale"], "rationale", 2000),
                _text(review["reviewer"], "reviewer"),
            ):
                raise ValueError("reviewed answer commitment failed integrity checks")
            draft = attach_learned_operator(base, bound["node_id"], expected)
            if (digest(row.get("refined_artifact")) != digest(expected)
                    or digest(row.get("draft")) != digest(draft.to_dict())):
                raise ValueError("operator refinement failed integrity checks")
            lineage = row.get("lineage")
            if not isinstance(lineage, dict) or digest(lineage) != digest(
                OperatorReviewService._lineage(row, review, expected, draft),
            ):
                raise ValueError("operator refinement lineage failed integrity checks")
        elif row["status"] != ("awaiting_answer" if query_status == "found" else query_status):
            raise ValueError("invalid operator question state")
        elif any(row.get(key) is not None for key in ("review", "refined_artifact", "draft", "lineage")):
            raise ValueError("unanswered question contains a refinement")

    @staticmethod
    def _lineage(row: dict, review: dict, artifact: dict, draft: Flow) -> dict:
        return {
            "schema": LINEAGE_SCHEMA, "parent_artifact_sha256": row["binding"]["artifact_sha256"],
            "question_sha256": row["question"]["question_sha256"],
            "review_sha256": digest(review), "artifact_sha256": artifact["artifact_sha256"],
            "draft_sha256": digest(draft.to_dict()),
            "source_flow_sha256": row["binding"]["flow_sha256"],
            "candidates_before": row["question"]["candidate_count"],
            "candidates_after": candidate_count(artifact),
        }

    def _recover(self, row: dict) -> dict:
        if row.get("_audit_pending"):
            # Existing outbox delivery is idempotent and does not alter the
            # application revision or replay a reviewed transition.
            self.records.retry_pending(limit=MAX_RECORDS)
            current = self.records.get(row["id"])
            if current is None:
                raise LookupError("operator review is unavailable")
            return current
        return row

    @staticmethod
    def _present(row: dict) -> dict:
        if row.get("_audit_pending"):
            return {"schema": SCHEMA, "id": row["id"], "revision": row["revision"],
                    "status": "audit_pending", "committed_status": row["status"],
                    "audit_status": "pending", "binding": copy.deepcopy(row["binding"])}
        result = copy.deepcopy(row)
        result["audit_status"] = "delivered"
        return result

    def _load(self, ctx: ServiceContext, question_id: str, capability: str, *, human=False,
              require_current=True) -> dict:
        if type(question_id) is not str or not _ID.fullmatch(question_id):
            raise ValueError("invalid operator question ID")
        row = self.records.get(question_id)
        if row is None:
            raise LookupError("operator review is unavailable")
        self._permit(ctx, capability, row["binding"]["flow_id"], human=human)
        self._verify(ctx, row)
        # A source edit cannot strand the receipt for an already committed
        # question/answer. Current ownership is still mandatory before recovery;
        # source freshness is checked afterward for any new answer or export.
        self._flow(ctx, row["binding"]["flow_id"])
        row = self._recover(row)
        self._verify(ctx, row)
        self._permit(ctx, capability, row["binding"]["flow_id"], human=human)
        self._flow(ctx, row["binding"]["flow_id"])
        if require_current:
            self._current(ctx, row)
        return row

    def request(self, ctx: ServiceContext, flow_id: str, node_id: str, *, max_probes=256,
                expected_flow_version: int | None = None,
                expected_flow_revision: str | None = None) -> dict:
        from ..learning_guard import check_learning_halt
        from .operator_queries import propose_question

        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        with tenant_scope(tenant=ctx.tenant):
            self._gate(ctx)
            flow_id, node_id = _text(flow_id, "flow_id"), _text(node_id, "node_id")
            self._permit(ctx, "flow.operator.request", flow_id)
            flow = self._flow(ctx, flow_id)
            if expected_flow_version is not None and flow.version != _revision(expected_flow_version):
                raise OperatorReviewConflict("source flow version changed")
            if expected_flow_revision is not None and flow.revision != _text(expected_flow_revision, "flow revision"):
                raise OperatorReviewConflict("source flow generation changed")
            bound = _binding(ctx, flow, node_id)
            check_learning_halt("flow_operator_questions", "question")
            question = propose_question(flow.nodes[node_id].learned_operator["artifact"], max_probes=max_probes)
            identity = digest({"binding": bound, "question_sha256": question["question_sha256"]})
            row = {"schema": SCHEMA, "id": "LOQ-" + identity[:32], "binding": bound,
                   "base_flow": flow.to_dict(), "question": question, "requested_by": ctx.actor,
                   "status": "awaiting_answer" if question["status"] == "found" else question["status"],
                   "review": None, "refined_artifact": None, "draft": None, "lineage": None}
            self._verify(ctx, row)
            existing = self.records.get(row["id"])
            if existing is not None:
                return self._present(self._load(ctx, row["id"], "flow.operator.request"))
            self._permit(ctx, "flow.operator.request", flow_id)
            self._current(ctx, row)
            check_learning_halt("flow_operator_questions", "request_commit")
            try:
                saved = self.records.create(row, action="operator_question_requested", actor=ctx.actor,
                                            max_records=MAX_RECORDS)
            except RecordConflict:
                saved = self.records.get(row["id"])
                if saved is None:
                    raise
                self._verify(ctx, saved)
            self._permit(ctx, "flow.operator.request", flow_id)
            self._current(ctx, saved)
            return self._present(saved)

    def get(self, ctx: ServiceContext, question_id: str) -> dict:
        """Read retained evidence for the current owner, even after source edits.

        Stale historical evidence is marked explicitly and does not expose a
        usable draft or refined artifact. Answer/export require exact freshness.
        """
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        with tenant_scope(tenant=ctx.tenant):
            self._gate(ctx)
            row = self._load(ctx, question_id, "flow.operator.read", require_current=False)
            result = self._present(row)
            try:
                self._current(ctx, row)
            except (OperatorReviewConflict, ValueError):
                result["source_current"] = False
                result.pop("draft", None)
                result.pop("refined_artifact", None)
            else:
                result["source_current"] = True
            return result

    def answer(self, ctx: ServiceContext, question_id: str, output: Any, *, expected_revision: int,
               rationale: str) -> dict:
        from ..learning_guard import check_learning_halt
        from .operator_queries import answer_question

        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        with tenant_scope(tenant=ctx.tenant):
            self._gate(ctx)
            expected_revision = _revision(expected_revision)
            rationale = _text(rationale, "rationale", 2000)
            row = self._load(ctx, question_id, "flow.operator.answer", human=True)
            if row["status"] == "draft_ready":
                reviewed = row["review"]
                if (type(output) is not type(reviewed["output"]) or output != reviewed["output"]
                        or rationale != reviewed["rationale"] or ctx.actor != reviewed["reviewer"]):
                    raise OperatorReviewConflict("question already has a different reviewed answer")
                return self._present(row)
            if row.get("_audit_pending"):
                raise OperatorReviewAuditPending(question_id)
            if row["status"] != "awaiting_answer":
                raise OperatorReviewConflict("question does not await an answer")
            if row["revision"] != expected_revision:
                raise OperatorReviewConflict("operator question revision changed")
            check_learning_halt("flow_operator_questions", "refine")
            base = Flow.from_dict(row["base_flow"])
            artifact = base.nodes[row["binding"]["node_id"]].learned_operator["artifact"]
            refined = answer_question(artifact, row["question"], output)
            # The pure engine validates scalar type/size before this digest or
            # durable copy; request bodies cannot smuggle arbitrary containers.
            request_sha256 = _answer_digest(row["question"], output, rationale, ctx.actor)
            draft = attach_learned_operator(base, row["binding"]["node_id"], refined)
            review = {"human": True, "reviewer": ctx.actor, "output": copy.deepcopy(output),
                      "rationale": rationale, "reviewed_at": self.clock(),
                      "authority_sha256": digest(ctx.binding()), "request_sha256": request_sha256}
            lineage = self._lineage(row, review, refined, draft)

            def mutate(current: dict) -> None:
                self._verify(ctx, current)
                if current["status"] != "awaiting_answer":
                    raise OperatorReviewConflict("question already has a reviewed answer")
                self._permit(ctx, "flow.operator.answer", current["binding"]["flow_id"], human=True)
                self._current(ctx, current)
                check_learning_halt("flow_operator_questions", "answer_commit")
                current.update(status="draft_ready", review=review, refined_artifact=refined,
                               draft=draft.to_dict(), lineage=lineage)

            try:
                saved = self.records.update(question_id, mutate, expected_revision=expected_revision,
                                            action="operator_question_answered", actor=ctx.actor)
            except RecordConflict:
                current = self.records.get(question_id)
                if current is None or (current.get("review") or {}).get("request_sha256") != request_sha256:
                    raise
                self._verify(ctx, current)
                self._current(ctx, current)
                saved = self._recover(current)
            if saved is None:
                raise LookupError("operator review is unavailable")
            self._permit(ctx, "flow.operator.answer", saved["binding"]["flow_id"], human=True)
            self._current(ctx, saved)
            return self._present(saved)

    def export_draft(self, ctx: ServiceContext, question_id: str) -> Flow:
        if not isinstance(ctx, ServiceContext):
            raise TypeError("explicit ServiceContext required")
        with tenant_scope(tenant=ctx.tenant):
            self._gate(ctx)
            row = self._load(ctx, question_id, "flow.operator.export")
            if row.get("_audit_pending"):
                raise OperatorReviewAuditPending(question_id)
            if row["status"] != "draft_ready":
                raise OperatorReviewConflict("question has no reviewed draft")
            return Flow.from_dict(copy.deepcopy(row["draft"]))


__all__ = ["OperatorReviewService", "OperatorReviewConflict", "OperatorReviewAuditPending"]
