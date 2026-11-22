"""Matter-scoped legal operations with atomic revisions and audited mutations.

Each matter is one governed aggregate. Access changes, state transitions and
their idempotency receipts share the same CAS boundary on both native stores.
No company-wide knowledge or external connector is searched implicitly.
"""
from __future__ import annotations

import copy
import hashlib
import secrets
import time
from datetime import date, timedelta
from decimal import Decimal

from . import config
from .governed_operations import digest
from .governed_records import GovernedRecordStore, RecordConflict
from .legal_workforce_catalog import ROLE_MAP, ROLES, suggested_roles
from .legal_workspace_models import OPERATIONS
from .paths import current_tenant_id_strict

STORE = GovernedRecordStore("legal-workspace", "LGL", "legal_matter", archive_when_full=False)
COLLECTIONS = ("sources", "contracts", "obligations", "engagements", "invoices", "assignments", "decisions", "packets")
REVIEW_ACTIONS = {"access", "review_obligation", "review_engagement", "edit_engagement", "review_invoice", "review_assignment", "review_decision", "run", "packet"}


def enabled():
    return (not config.config_source_errors(include_tenant=True)
            and config.load_config().get("legal_workspace", {}).get("enable") is True)


def clean(row):
    return {key: copy.deepcopy(value) for key, value in row.items() if not key.startswith("_")}


def item(row, collection, identity):
    found = next((entry for entry in row[collection] if entry["id"] == identity), None)
    if found is None:
        raise ValueError("The selected record is unavailable in this matter.")
    return found


def validate_dates(arguments):
    value = arguments.get("due_date")
    if value:
        try:
            if date.fromisoformat(value).isoformat() != value:
                raise ValueError
        except ValueError as exc:
            raise ValueError("Use a valid calendar date in year-month-day form.") from exc


def _append(row, collection, value):
    if len(row[collection]) >= 200:
        raise ValueError("This matter has reached its record limit. Export and split the work into a related matter.")
    value = {"id": secrets.token_hex(12), **value}
    row[collection].append(value)
    return value


def _source(row, identity):
    return item(row, "sources", identity)


def _contract(row, args):
    source = _source(row, args["source_id"])
    if source["kind"] not in {"agreement", "amendment"}:
        raise ValueError("Choose an agreement or amendment as the contract source.")
    if args["stage"] == "executed":
        if source["status"] != "executed":
            raise ValueError("Add the executed agreement as evidence before recording execution.")
        decisions = {entry["kind"] for entry in row["decisions"] if entry["state"] == "approved"
                     and entry.get("contract_id") == args.get("contract_id")
                     and entry.get("contract_source_id") == args["source_id"]}
        if not {"legal", "commercial", "signing"} <= decisions:
            raise ValueError("Record the legal, commercial and signing approvals for this contract first.")
    if "contract_id" in args:
        contract = item(row, "contracts", args["contract_id"])
        if contract["stage"] == "terminated" and args["stage"] != "terminated":
            raise ValueError("Register a new agreement after termination.")
        contract.setdefault("versions", []).append({key: contract[key] for key in ("source_id", "stage", "open_issues")})
        contract.update({key: value for key, value in args.items() if key != "contract_id"})
        return contract
    return _append(row, "contracts", args)


def _engagement_review(row, args, actor):
    engagement = item(row, "engagements", args["engagement_id"])
    transitions = {"proposed": {"conflicts_cleared"}, "conflicts_cleared": {"approved"},
                   "approved": {"in_progress", "advice_received"}, "in_progress": {"advice_received"},
                   "advice_received": {"closed"}, "closed": set()}
    if args["state"] not in transitions[engagement["state"]]:
        raise ValueError("Record conflict clearance, approval and receipt of advice in order before closing.")
    engagement.update(state=args["state"], note=args["note"], reviewed_by=actor)
    return engagement


def _invoice(row, args):
    engagement = item(row, "engagements", args["engagement_id"])
    if engagement["state"] not in {"approved", "in_progress", "advice_received", "closed"}:
        raise ValueError("Approve the engagement before recording its invoices.")
    previous = [entry for entry in row["invoices"] if entry["engagement_id"] == engagement["id"]]
    if any(entry["reference"].casefold() == args["reference"].casefold() for entry in previous):
        raise ValueError("This invoice reference is already recorded for the engagement.")
    exceptions = []
    if sum(entry["amount"] for entry in previous) + args["amount"] > engagement["budget"]:
        exceptions.append("Recorded invoices exceed the engagement budget.")
    if engagement["max_hourly_rate"] and args["hourly_rate"] > engagement["max_hourly_rate"]:
        exceptions.append("The billed hourly rate exceeds the agreed maximum.")
    if engagement["max_hourly_rate"] and not args["hourly_rate"]:
        exceptions.append("The billed hourly rate was not supplied; compare the invoice with agreed rates.")
    return _append(row, "invoices", {**args, "currency": engagement["currency"], "state": "awaiting_review", "exceptions": exceptions})


def _edit_engagement(row, args):
    engagement = item(row, "engagements", args["engagement_id"])
    if engagement["state"] == "closed":
        raise ValueError("Create a new engagement after closure.")
    if args["currency"] != engagement["currency"] and any(i["engagement_id"] == engagement["id"] for i in row["invoices"]):
        raise ValueError("An engagement with invoices must retain its original currency.")
    engagement.setdefault("versions", []).append({key: engagement[key] for key in ("scope", "deliverables", "budget", "state")})
    engagement.update({key: value for key, value in args.items() if key != "engagement_id"})
    engagement["state"] = "proposed"
    return engagement


def _assignment(row, args, actor):
    if args["role_id"] not in ROLE_MAP:
        raise ValueError("Choose an available digital worker.")
    if len(set(args["source_ids"])) != len(args["source_ids"]):
        raise ValueError("Choose each source once.")
    sources = [_source(row, identity) for identity in args["source_ids"]]
    if sum(len(source["text"]) for source in sources) > 120000:
        raise ValueError("Select a smaller evidence packet (at most 120,000 characters).")
    return _append(row, "assignments", {**args, "state": "queued", "supervisor": row["owner"],
                                       "assigned_by": actor, "attempts": [], "review_note": ""})


def _review_assignment(row, args, actor):
    assignment = item(row, "assignments", args["assignment_id"])
    allowed = {"accepted": {"awaiting_review"}, "changes_requested": {"awaiting_review"},
               "cancelled": {"queued", "running", "awaiting_review", "changes_requested", "failed"}}
    if assignment["state"] not in allowed[args["state"]]:
        raise ValueError("This assignment cannot make that transition from its current state.")
    if args["state"] == "accepted" and assignment.get("citation_errors"):
        raise ValueError("Request corrections to unmatched citations before accepting this draft.")
    assignment.update(state=args["state"], review_note=args["note"], reviewed_by=actor)
    return assignment


def _review_simple(row, args, actor, collection, key):
    record = item(row, collection, args[key])
    if collection == "obligations":
        if args["state"] == "completed" and record["state"] != "confirmed":
            raise ValueError("Confirm the obligation and its date before completing it.")
        if record["state"] == "completed":
            raise ValueError("This obligation is already completed.")
    elif collection == "decisions" and record["state"] != "pending":
        raise ValueError("This decision is already recorded. Create a new decision if circumstances change.")
    record.update(state=args["state"], review_note=args.get("reason", args.get("note", "")), reviewed_by=actor)
    return record


def _packet(row, args, actor):
    engagement = item(row, "engagements", args["engagement_id"])
    if engagement["state"] not in {"approved", "in_progress", "advice_received"}:
        raise ValueError("Approve the engagement before preparing a packet for outside counsel.")
    if len(set(args["source_ids"])) != len(args["source_ids"]):
        raise ValueError("Choose each source once.")
    for identity in args["source_ids"]:
        _source(row, identity)
    return _append(row, "packets", {**args, "recipient": engagement["contact"], "firm": engagement["firm"],
                                  "prepared_by": actor, "prepared_at": time.time(), "state": "prepared"})


def _edit_matter(row, args):
    if args["status"] == "closed":
        open_work = any(a["state"] not in {"accepted", "cancelled"} for a in row["assignments"])
        open_work |= any(d["state"] == "pending" for d in row["decisions"])
        open_work |= any(o["state"] != "completed" for o in row["obligations"])
        open_work |= any(e["state"] != "closed" for e in row["engagements"])
        open_work |= any(i["state"] != "accepted" for i in row["invoices"])
        if open_work:
            raise ValueError("Resolve assignments, decisions, obligations, engagements and invoices before closing.")
    row.update(args)
    return row


def apply_operation(row, action, args, actor):
    """Apply a validated internal mutation; no provider, shell or external effects."""
    if action == "edit_matter":
        return _edit_matter(row, args)
    if action == "access":
        if args["principal"] == row["owner"]:
            raise ValueError("The supervising counsel retains access to the matter.")
        members = set(row["members"])
        members.add(args["principal"]) if args["grant"] else members.discard(args["principal"])
        row["members"] = sorted(members)
        return row
    if action == "source":
        if sum(len(s["text"]) for s in row["sources"]) + len(args["text"]) > 500000:
            raise ValueError("The matter evidence limit is 500,000 characters. Split the work into a related matter.")
        return _append(row, "sources", {**args, "sha256": hashlib.sha256(args["text"].encode()).hexdigest(), "added_by": actor})
    if action == "packet":
        return _packet(row, args, actor)
    if action in {"contract", "edit_contract"}:
        return _contract(row, args)
    if action == "obligation":
        if args["quote"] not in _source(row, args["source_id"])["text"]:
            raise ValueError("The supporting passage must match the selected source exactly.")
        return _append(row, "obligations", {**args, "state": "proposed"})
    if action == "engagement":
        return _append(row, "engagements", {**args, "state": "proposed"})
    if action == "review_engagement":
        return _engagement_review(row, args, actor)
    if action == "edit_engagement":
        return _edit_engagement(row, args)
    if action == "invoice":
        return _invoice(row, args)
    if action == "assignment":
        return _assignment(row, args, actor)
    if action == "review_assignment":
        return _review_assignment(row, args, actor)
    if action == "decision":
        if args["contract_id"]:
            contract = item(row, "contracts", args["contract_id"])
            args = {**args, "contract_source_id": contract["source_id"]}
        return _append(row, "decisions", {**args, "state": "pending"})
    review_types = {"review_obligation": ("obligations", "obligation_id"),
                    "review_invoice": ("invoices", "invoice_id"), "review_decision": ("decisions", "decision_id")}
    if action in review_types:
        return _review_simple(row, args, actor, *review_types[action])
    raise ValueError("Choose a supported legal operation.")


class LegalService:
    def __init__(self, tenant, actor, *, human, authorize):
        self.tenant, self.actor, self.human, self.authorize = tenant, actor, human, authorize

    def guard(self):
        if (not self.tenant or not self.actor or current_tenant_id_strict() != self.tenant
                or not enabled() or self.authorize() is not True):
            raise PermissionError("Legal workspace access is unavailable.")

    def access(self, row):
        self.guard()
        if row is None or row.get("tenant") != self.tenant or self.actor not in {row["owner"], *row["members"]}:
            raise PermissionError("This matter is unavailable to your account.")

    def list_matters(self):
        self.guard()
        rows = STORE.list(limit=1001)
        if len(rows) > 1000:
            raise RuntimeError("The legal matter inventory exceeds its supported limit.")
        visible = [clean(row) for row in rows if row.get("tenant") == self.tenant
                   and self.actor in {row["owner"], *row["members"]}]
        self.record_access("legal_inventory_read", shown=len(visible))
        return visible

    def get(self, identity):
        row = STORE.get(identity)
        self.access(row)
        self.record_access("legal_matter_read", matter_id=identity, revision=row["revision"])
        return clean(row)

    def record_access(self, verb, **details):
        from .audit import EventKind, audit_event
        if not audit_event(EventKind.CONTROL_PLANE_ACTION, agent="legal-workspace", verb=verb,
                           actor=self.actor, **details):
            raise RuntimeError("The matter access could not be recorded.")

    def export(self, identity, packet_id=""):
        row = self.get(identity)
        if packet_id:
            packet = item(row, "packets", packet_id)
            value = {**packet, "sources": [_source(row, source) for source in packet["source_ids"]],
                     "notice": "Prepared for counsel review and controlled delivery. This packet has not been sent."}
        else:
            value = row
        self.record_access("legal_packet_export" if packet_id else "legal_matter_export", matter_id=identity,
                           revision=row["revision"], packet_id=packet_id)
        return value

    def _authorize_write(self, row, action):
        self.access(row)
        if not self.human:
            raise PermissionError("A signed-in person must confirm legal workspace changes.")
        if (action in REVIEW_ACTIONS or action == "edit_matter") and self.actor != row["owner"]:
            raise PermissionError("The supervising counsel must review this operation.")
        if row["status"] == "closed" and action not in {"edit_matter", "access"}:
            raise ValueError("Reopen the matter before adding or changing its work.")

    def prepare(self, action, arguments, matter_id=""):
        self.guard()
        if action not in OPERATIONS:
            raise ValueError("Choose a supported legal operation.")
        args = OPERATIONS[action][1].model_validate(arguments).model_dump()
        validate_dates(args)
        for key in ("budget", "max_hourly_rate", "amount", "hourly_rate"):
            if key in args:
                cents = Decimal(str(args[key])) * 100
                if cents != cents.to_integral_value():
                    raise ValueError("Use monetary amounts with at most two decimal places.")
                args[key] = int(cents)
        if action == "create_matter":
            if not self.human:
                raise PermissionError("A person must open the matter.")
            revision = 0
        else:
            row = self.get(matter_id)
            self._authorize_write(row, action)
            revision = row["revision"]
            if action == "run":
                from .legal_workspace_runtime import prepare_run
                args = prepare_run(row, args)
            else:
                apply_operation(copy.deepcopy(row), action, args, self.actor)
        return {"action": action, "arguments": args, "matter_id": matter_id, "revision": revision,
                "tenant": self.tenant, "actor": self.actor}

    def recover(self, material, operation_id):
        self.guard()
        if material["tenant"] != self.tenant or material["actor"] != self.actor:
            raise PermissionError("Return to the original account and workspace.")
        identity = material["matter_id"] or "LGL-" + digest({"actor": self.actor, "operation": operation_id})[:32]
        row = STORE.get(identity)
        if row is None:
            return None
        self.access(row)
        receipt = row["_operations"].get(operation_id)
        if receipt is None:
            return None
        if receipt["digest"] != digest(material):
            raise RecordConflict("This action reference belongs to different work.")
        return clean(row)

    def execute(self, material, operation_id):
        original = self.recover(material, operation_id)
        if original is not None:
            return original
        self.guard()
        if not self.human:
            raise PermissionError("A signed-in person must confirm this work.")
        if material["action"] == "run":
            from .legal_workspace_runtime import run_assignment
            return run_assignment(self, material, operation_id)
        if material["action"] == "create_matter":
            row = {"id": "LGL-" + digest({"actor": self.actor, "operation": operation_id})[:32],
                   "tenant": self.tenant, "owner": self.actor, "members": [], "status": "intake",
                   **material["arguments"], **{name: [] for name in COLLECTIONS},
                   "_operations": {operation_id: {"digest": digest(material)}}, "events": []}
            saved = STORE.create(row, action="legal_matter_created", actor=self.actor, max_records=1000, effect_guard=self.guard)
        else:
            def mutate(row):
                self._authorize_write(row, material["action"])
                apply_operation(row, material["action"], material["arguments"], self.actor)
                self.receipt(row, material, operation_id)
            saved = STORE.update(material["matter_id"], mutate, expected_revision=material["revision"],
                                 action="legal_" + material["action"], actor=self.actor, effect_guard=self.guard)
        if saved is None:
            raise RecordConflict("The matter is no longer available.")
        return clean(saved)

    def receipt(self, row, material, operation_id):
        if len(row["_operations"]) >= 2000:
            raise ValueError("This matter reached its operation limit. Export and continue in a related matter.")
        row["_operations"][operation_id] = {"digest": digest(material)}
        row["events"].append({"action": material["action"], "actor": self.actor, "at": time.time()})

    def overview(self):
        rows = self.list_matters()
        today = date.today().isoformat()
        soon = (date.today() + timedelta(days=30)).isoformat()
        attention, spend, assignments = [], {}, []
        for row in rows:
            for collection in ("obligations", "decisions", "engagements", "assignments", "invoices"):
                for entry in row[collection]:
                    state = entry.get("state")
                    if state in {"completed", "accepted", "cancelled", "closed", "rejected"} or state == "approved" and collection == "decisions":
                        continue
                    due = entry.get("due_date", "")
                    if due and due <= soon or state in {"pending", "proposed", "awaiting_review", "failed"}:
                        attention.append({"matter_id": row["id"], "matter": row["title"], "kind": collection,
                                          "title": entry.get("title", entry.get("firm", entry.get("reference", "Review needed"))),
                                          "state": state, "due_date": due, "overdue": bool(due and due < today)})
            for engagement in row["engagements"]:
                totals = spend.setdefault(engagement["currency"], {"budget": 0, "invoiced": 0})
                totals["budget"] += engagement["budget"]
                billed = sum(invoice["amount"] for invoice in row["invoices"] if invoice["engagement_id"] == engagement["id"])
                if billed > engagement["budget"]:
                    attention.append({"matter_id": row["id"], "matter": row["title"], "kind": "budget",
                                      "title": engagement["firm"] + " — budget exceeded", "state": "over_budget", "due_date": "", "overdue": False})
            for contract in row["contracts"]:
                if contract["stage"] in {"review", "negotiation", "approval"} and contract["open_issues"]:
                    attention.append({"matter_id": row["id"], "matter": row["title"], "kind": "contracts",
                                      "title": contract["title"], "state": contract["stage"], "due_date": "", "overdue": False})
            for invoice in row["invoices"]:
                spend.setdefault(invoice["currency"], {"budget": 0, "invoiced": 0})["invoiced"] += invoice["amount"]
            assignments.extend(row["assignments"])
        performance = [{**role, "assignments": sum(a["role_id"] == role["id"] for a in assignments),
                        "accepted": sum(a["role_id"] == role["id"] and a["state"] == "accepted" for a in assignments),
                        "corrections": sum(a["role_id"] == role["id"] and a["state"] == "changes_requested" for a in assignments)} for role in ROLES]
        return {"matters": [{key: row[key] for key in ("id", "title", "area", "status", "priority", "department", "business_owner", "due_date", "owner", "revision")} for row in rows],
                "attention": sorted(attention, key=lambda entry: (not entry["overdue"], entry["due_date"] or "9999")),
                "spend": spend, "workers": performance,
                "suggestions": {row["id"]: suggested_roles(row["area"]) for row in rows}, "as_of": today}
