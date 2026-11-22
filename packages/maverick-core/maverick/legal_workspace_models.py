"""Validated inputs shared by legal services, dashboard and Copilot."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Area = Literal["commercial", "corporate", "transactions", "employment", "product_privacy",
               "regulatory", "disputes", "investigations", "intellectual_property", "outside_counsel"]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    @field_validator("*", mode="before")
    @classmethod
    def trim_strings(cls, value):
        return value.strip() if isinstance(value, str) else value


class MatterInput(Input):
    title: str = Field(min_length=1, max_length=200, title="Matter name")
    area: Area = Field(title="Legal area")
    objective: str = Field(min_length=1, max_length=4000, title="Business objective")
    department: str = Field(min_length=1, max_length=120, title="Requesting department")
    business_owner: str = Field(min_length=1, max_length=120, title="Business owner")
    jurisdiction: str = Field(min_length=1, max_length=200, title="Jurisdiction or unresolved jurisdiction question")
    priority: Literal["routine", "important", "urgent"] = "routine"
    due_date: str = Field(default="", max_length=10, title="Business target date")


class MatterEdit(MatterInput):
    status: Literal["intake", "active", "waiting_business", "waiting_counsel", "closed"] = "intake"


class AccessInput(Input):
    principal: str = Field(min_length=1, max_length=200, title="Workspace member")
    grant: bool = Field(default=True, title="Allow access to this matter")


class SourceInput(Input):
    title: str = Field(min_length=1, max_length=200, title="Document or source name")
    kind: Literal["agreement", "amendment", "playbook", "correspondence", "authority", "counsel_advice", "record"] = "record"
    reference: str = Field(min_length=1, max_length=1000, title="Source reference (file, page, section or origin)")
    text: str = Field(min_length=1, max_length=100000, title="Source text")
    status: Literal["draft", "executed", "approved", "unverified"] = "unverified"


class ContractInput(Input):
    title: str = Field(min_length=1, max_length=200, title="Contract name")
    counterparty: str = Field(min_length=1, max_length=200, title="Counterparty")
    source_id: str = Field(min_length=1, max_length=80, title="Agreement source")
    stage: Literal["request", "review", "negotiation", "approval", "executed", "terminated"] = "request"
    commercial_owner: str = Field(min_length=1, max_length=120, title="Commercial owner")
    open_issues: str = Field(default="", max_length=4000, title="Open issues and proposed concessions")


class ContractEdit(ContractInput):
    contract_id: str = Field(min_length=1, max_length=80, title="Contract")


class ObligationInput(Input):
    title: str = Field(min_length=1, max_length=200, title="Obligation or deadline")
    source_id: str = Field(min_length=1, max_length=80, title="Supporting source")
    quote: str = Field(min_length=1, max_length=3000, title="Exact supporting passage")
    owner: str = Field(min_length=1, max_length=120, title="Responsible person")
    due_date: str = Field(min_length=10, max_length=10, title="Proposed due date")
    basis: str = Field(min_length=1, max_length=2000, title="Date basis, trigger and calculation")


class ObligationReview(Input):
    obligation_id: str = Field(min_length=1, max_length=80, title="Obligation")
    state: Literal["confirmed", "completed", "disputed"]
    reason: str = Field(min_length=1, max_length=2000, title="Review note or completion evidence")


class EngagementInput(Input):
    firm: str = Field(min_length=1, max_length=200, title="Outside firm")
    contact: str = Field(min_length=1, max_length=200, title="Counsel contact")
    scope: str = Field(min_length=1, max_length=4000, title="Assignment and questions to answer")
    deliverables: str = Field(min_length=1, max_length=4000, title="Required deliverables")
    due_date: str = Field(default="", max_length=10, title="Expected delivery date")
    budget: float = Field(ge=0, le=10000000, allow_inf_nan=False, title="Approved budget")
    currency: str = Field(pattern=r"^[A-Z]{3}$", default="USD", title="Currency")
    max_hourly_rate: float = Field(default=0, ge=0, le=100000, allow_inf_nan=False, title="Maximum agreed hourly rate (zero if not applicable)")


class EngagementReview(Input):
    engagement_id: str = Field(min_length=1, max_length=80, title="Engagement")
    state: Literal["conflicts_cleared", "approved", "in_progress", "advice_received", "closed"]
    note: str = Field(min_length=1, max_length=2000, title="Clearance, approval or progress evidence")


class EngagementEdit(EngagementInput):
    engagement_id: str = Field(min_length=1, max_length=80, title="Engagement")


class InvoiceInput(Input):
    engagement_id: str = Field(min_length=1, max_length=80, title="Engagement")
    reference: str = Field(min_length=1, max_length=120, title="Invoice reference")
    amount: float = Field(ge=0, le=10000000, allow_inf_nan=False, title="Invoice amount")
    hourly_rate: float = Field(default=0, ge=0, le=100000, allow_inf_nan=False, title="Highest billed hourly rate")
    description: str = Field(min_length=1, max_length=2000, title="Work billed and supporting reference")


class InvoiceReview(Input):
    invoice_id: str = Field(min_length=1, max_length=80, title="Invoice")
    state: Literal["accepted", "disputed"]
    note: str = Field(min_length=1, max_length=2000, title="Review rationale (does not release payment)")


class AssignmentInput(Input):
    role_id: str = Field(min_length=1, max_length=80, title="Digital worker")
    title: str = Field(min_length=1, max_length=200, title="Assignment")
    instructions: str = Field(min_length=1, max_length=4000, title="Requested work and completion criteria")
    source_ids: list[str] = Field(min_length=1, max_length=20, title="Approved evidence")
    due_date: str = Field(default="", max_length=10, title="Target date")


class RunInput(Input):
    assignment_id: str = Field(min_length=1, max_length=80, title="Assignment")
    max_dollars: float = Field(gt=0, le=100, default=1.0, title="Maximum AI cost (USD)")
    max_seconds: int = Field(ge=30, le=600, default=120, title="Maximum run time (seconds)")


class AssignmentReview(Input):
    assignment_id: str = Field(min_length=1, max_length=80, title="Assignment")
    state: Literal["accepted", "changes_requested", "cancelled"]
    note: str = Field(min_length=1, max_length=4000, title="Review feedback")


class DecisionInput(Input):
    kind: Literal["legal", "commercial", "signing", "conflict", "other"]
    title: str = Field(min_length=1, max_length=200, title="Decision needed")
    owner: str = Field(min_length=1, max_length=200, title="Decision owner")
    options: str = Field(min_length=1, max_length=4000, title="Options and consequences")
    due_date: str = Field(default="", max_length=10, title="Decision target date")
    contract_id: str = Field(default="", max_length=80, title="Related contract (optional)")


class DecisionReview(Input):
    decision_id: str = Field(min_length=1, max_length=80, title="Decision")
    state: Literal["approved", "rejected"]
    reason: str = Field(min_length=1, max_length=4000, title="Decision and rationale")


class PacketInput(Input):
    engagement_id: str = Field(min_length=1, max_length=80, title="Approved engagement")
    title: str = Field(min_length=1, max_length=200, title="Counsel packet name")
    instructions: str = Field(min_length=1, max_length=4000, title="Instructions to outside counsel")
    source_ids: list[str] = Field(min_length=1, max_length=20, title="Evidence approved for this packet")


OPERATIONS = {
    "create_matter": ("Open a legal request", MatterInput),
    "edit_matter": ("Update matter and status", MatterEdit),
    "access": ("Change matter access", AccessInput),
    "source": ("Add source evidence", SourceInput),
    "contract": ("Register a contract", ContractInput),
    "edit_contract": ("Update contract and negotiation", ContractEdit),
    "obligation": ("Propose an obligation or deadline", ObligationInput),
    "review_obligation": ("Confirm or complete an obligation", ObligationReview),
    "engagement": ("Prepare an outside counsel engagement", EngagementInput),
    "review_engagement": ("Record engagement progress or approval", EngagementReview),
    "edit_engagement": ("Revise counsel scope or budget for reapproval", EngagementEdit),
    "invoice": ("Check an outside counsel invoice", InvoiceInput),
    "review_invoice": ("Review an invoice exception", InvoiceReview),
    "assignment": ("Assign a digital legal worker", AssignmentInput),
    "run": ("Run the selected digital worker", RunInput),
    "review_assignment": ("Review or cancel an assignment", AssignmentReview),
    "decision": ("Request a business or legal decision", DecisionInput),
    "review_decision": ("Record a decision", DecisionReview),
    "packet": ("Prepare an outside counsel evidence packet", PacketInput),
}
